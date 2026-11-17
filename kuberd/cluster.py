import ipaddress
import logging
import time
from dataclasses import dataclass, field

import docker
from docker.errors import DockerException, NotFound

from kuberd.config import ClusterConfig
from kuberd.constants import (
    PKI_HELPER_IMAGE,
    K8S_DIR,
    ETCD_DATA_DIR,
    EGRESS_CONFIG,
    API_PORT,
    KONNECTIVITY_SERVER_PORT,
    KONNECTIVITY_AGENT_PORT,
    LOCAL_API_IP,
    CREATE_PKI_FILES,
    LABEL,
    COMPONENTS,
    TOOLBOX,
    HELPERS,
    RESTART_POLICY,
    STOPPED_STATES,
)
from kuberd.container import Container
from kuberd.kubeadm import (
    PKIConfig,
    generate_addons,
    generate_bootstrap_token_phase,
    generate_cluster_admins_rbac,
    generate_cluster_kubeconfigs,
    generate_cluster_pki,
    generate_egress_selector_config,
    generate_konnectivity_agent,
    generate_kubeconfig,
    generate_kubernetes_endpoints,
    generate_upload_config,
)
from kuberd.utils import (
    check_images_exist,
    files_in_command,
    is_permanent_kubectl_error,
    container_name,
    etcd_command,
    apiserver_command,
    controller_manager_command,
    konnectivity_command,
    scheduler_command,
    check_host_ports,
    build_toolbox_image,
    owned_by,
    file_mode,
)


log = logging.getLogger("kuberd")


# --- cluster -----------------------------------------------------------------


@dataclass
class Cluster:
    """Class that manages a Kubernetes control plane on Docker."""

    name: str
    config: ClusterConfig | None = None
    client: docker.DockerClient = field(default_factory=docker.from_env, repr=False, compare=False)
    containers: list[Container] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Check the name against the configuration and build the list of the cluster containers."""
        if self.config is not None and self.config.name != self.name:
            raise ValueError(
                f"cluster name {self.name!r} differs from the configuration name "
                f"{self.config.name!r}"
            )
        self.containers = [self._container_spec(c) for c in [*COMPONENTS, TOOLBOX]]

    # --- names -----------------------------------------------------------

    @property
    def labels(self) -> dict[str, str]:
        """Labels of the cluster resources."""
        return {LABEL: self.name}

    @property
    def network_name(self) -> str:
        """Name of the cluster network."""
        return self.name

    @property
    def pki_volume(self) -> str:
        """Name of the PKI volume."""
        return container_name(self.name, "pki")

    @property
    def etcd_data_volume(self) -> str:
        """Name of the etcd data volume."""
        return container_name(self.name, "etcd-data")

    def container_name(self, component: str) -> str:
        """Name of the container of a component."""
        return container_name(self.name, component)

    def container(self, component: str) -> Container:
        """Return the container of a component."""
        name = self.container_name(component)
        for container in self.containers:
            if container.name == name:
                return container
        known = ", ".join([*COMPONENTS, TOOLBOX])
        raise ValueError(f"unknown component {component!r} (one of {known})")

    @property
    def internal_server(self) -> str:
        """API server URL on the cluster network."""
        return f"https://{self.container_name('kube-apiserver')}:{API_PORT}"

    @property
    def local_server(self) -> str:
        """API server URL on the local host."""
        return f"https://{LOCAL_API_IP}:{self._require_config().ports.api}"

    @property
    def node_endpoint(self) -> str:
        """API server address used by the nodes."""
        config = self._require_config()
        return f"{config.node_endpoint_ip}:{config.ports.api}"

    @property
    def node_server(self) -> str:
        """API server URL used by the nodes."""
        return f"https://{self.node_endpoint}"

    def _require_config(self) -> ClusterConfig:
        """Return the cluster configuration."""
        if self.config is None:
            raise RuntimeError(f"cluster {self.name!r}: a configuration is required")
        return self.config

    # --- container specs -------------------------------------------------

    def _container_spec(self, component: str) -> Container:
        """Build the container of a component."""
        name = self.container_name(component)
        common = {"client": self.client, "labels": self.labels}
        if self.config is None:
            return Container(name, **common)
        common["restart_policy"] = RESTART_POLICY
        if component == TOOLBOX:
            return Container(
                name,
                image=self.config.versions.toolbox_image,
                network=self.network_name,
                hostname=name,
                **common,
            )

        config, versions = self.config, self.config.versions
        node_ip = config.node_endpoint_ip
        specs = {
            "etcd": (versions.etcd_image, etcd_command(self.name), None),
            "kube-apiserver": (
                versions.kubernetes_image("kube-apiserver"),
                apiserver_command(self.name, config.service_cidr, config.cluster_domain, node_ip),
                {
                    f"{API_PORT}/tcp": [
                        (node_ip, config.ports.api),
                        (LOCAL_API_IP, config.ports.api),
                    ]
                },
            ),
            "konnectivity-server": (
                versions.konnectivity_server_image,
                konnectivity_command(),
                {f"{KONNECTIVITY_AGENT_PORT}/tcp": (node_ip, config.ports.konnectivity)},
            ),
            "kube-controller-manager": (
                versions.kubernetes_image("kube-controller-manager"),
                controller_manager_command(self.name),
                None,
            ),
            "kube-scheduler": (
                versions.kubernetes_image("kube-scheduler"),
                scheduler_command(),
                None,
            ),
        }
        image, command, ports = specs[component]
        volumes = {self.pki_volume: {"bind": K8S_DIR, "mode": "ro"}}
        if component == "etcd":
            volumes[self.etcd_data_volume] = {"bind": ETCD_DATA_DIR, "mode": "rw"}
        return Container(
            name,
            image=image,
            command=command,
            volumes=volumes,
            network=self.network_name,
            ports=ports,
            hostname=name,
            # The image runs as non-root; the PKI keys in the volume are root-only.
            user="0" if component == "konnectivity-server" else None,
            **common,
        )

    # --- Docker resources ------------------------------------------------

    def _network(self):
        """Return the cluster network, or None."""
        for network in self.client.networks.list(names=[self.network_name]):
            if network.name == self.network_name:
                return network
        return None

    def _volume(self, name: str):
        """Return a volume by name, or None."""
        try:
            return self.client.volumes.get(name)
        except NotFound:
            return None

    def _docker_container(self, name: str):
        """Return a container by name, or None."""
        for container in self.client.containers.list(all=True, filters={"name": name}):
            if container.name == name:
                return container
        return None

    def _resources(self) -> list[tuple[str, str, object]]:
        """List the Docker resources of the cluster."""
        resources = [("network", self.network_name, self._network())]
        for volume in (self.pki_volume, self.etcd_data_volume):
            resources.append(("volume", volume, self._volume(volume)))
        for component in [*COMPONENTS, TOOLBOX, *HELPERS]:
            name = self.container_name(component)
            resources.append(("container", name, self._docker_container(name)))
        return resources

    def exists(self) -> bool:
        """Check whether the cluster exists."""
        selector = {"label": f"{LABEL}={self.name}"}
        return bool(
            self.client.containers.list(all=True, filters=selector)
            or self.client.volumes.list(filters=selector)
            or self.client.networks.list(filters=selector)
        )

    def _is_complete(self, resources: list | None = None) -> bool:
        """Check whether all the cluster resources exist."""
        return all(
            resource is not None and owned_by(resource, self.name)
            for kind, name, resource in resources or self._resources()
            if name not in {self.container_name(h) for h in HELPERS}
        )

    def _check_owner(self, resources: list | None = None) -> None:
        """Check that the resources with the cluster names belong to the cluster."""
        foreign = [
            f"{kind} {name}"
            for kind, name, resource in resources or self._resources()
            if resource is not None and not owned_by(resource, self.name)
        ]
        if foreign:
            raise RuntimeError(
                f"these Docker resources exist but do not belong to kuberd cluster "
                f"{self.name!r}: {', '.join(foreign)}; choose another cluster name"
            )

    def _ensure_volume(self, name: str) -> None:
        """Create a volume if it does not exist."""
        volume = self._volume(name)
        if volume is None:
            self.client.volumes.create(name, labels=self.labels)
        elif not owned_by(volume, self.name):
            raise RuntimeError(f"volume {name} does not belong to kuberd cluster {self.name!r}")

    # --- PKI volume ------------------------------------------------------

    def _pki_helper(self, mode: str) -> Container:
        """Build the container used to access the PKI volume."""
        return Container(
            self.container_name("pki-helper"),
            image=PKI_HELPER_IMAGE,
            volumes={self.pki_volume: {"bind": K8S_DIR, "mode": mode}},
            labels=self.labels,
            client=self.client,
        )

    def _write_pki(self, files: dict[str, bytes]) -> None:
        """Write files into the PKI volume."""
        self._ensure_volume(self.pki_volume)
        helper = self._pki_helper("rw")
        if helper.exists():
            helper.delete(force=True)
        helper.create()
        try:
            helper.put_files(
                {path: (content, file_mode(path)) for path, content in files.items()},
                dest=K8S_DIR,
            )
        finally:
            helper.delete(force=True)

    def read_pki(self) -> dict[str, bytes] | None:
        """Read the files of the PKI volume; return None if the volume is missing or empty."""
        volume = self._volume(self.pki_volume)
        if volume is None:
            return None
        if not owned_by(volume, self.name):
            raise RuntimeError(
                f"volume {volume.name} does not belong to kuberd cluster {self.name!r}"
            )
        helper = self._pki_helper("ro")
        if helper.exists():
            helper.delete(force=True)
        helper.create()
        try:
            files = helper.get_files(K8S_DIR)
        finally:
            helper.delete(force=True)
        # An empty volume (e.g. an interrupted write) counts as missing.
        return files or None

    # --- lifecycle -------------------------------------------------------

    def create(self) -> bool:
        """Create the cluster; return False if it already exists."""
        config = self._require_config()
        resources = self._resources()
        self._check_owner(resources)
        if self._is_complete(resources):
            return False
        self._preflight(config)

        pki_config = self._pki_config(config)
        material, kubeconfigs = self._load_or_generate_pki(pki_config)

        log.info("starting control plane")
        self._create_control_plane()

        log.info("applying kubeadm phases")
        self._apply_phases(config, pki_config, material["ca.crt"], kubeconfigs["super-admin.conf"])

        log.info("starting toolbox")
        # Same admin identity, but reaching the API server on the cluster network.
        self._create_toolbox(
            generate_kubeconfig(
                server=self.internal_server,
                ca_cert_pem=material["ca.crt"],
                user="kubernetes-admin",
                client_cert_pem=material["admin.crt"],
                client_key_pem=material["admin.key"],
            )
        )
        return True

    def _preflight(self, config: ClusterConfig) -> None:
        """Check host ports and images before creating the cluster."""
        bindings = []
        if not self.container("kube-apiserver").exists():
            bindings += [
                (config.node_endpoint_ip, config.ports.api),
                (LOCAL_API_IP, config.ports.api),
            ]
        if not self.container("konnectivity-server").exists():
            bindings += [(config.node_endpoint_ip, config.ports.konnectivity)]
        try:
            check_host_ports(bindings)
        except RuntimeError as e:
            key = "nodeEndpointIP" if "not an address" in str(e) else "apiPort / konnectivityPort"
            raise RuntimeError(f"{e}\nSet {key} in the configuration file.") from None
        # Versions are well-formed (checked by load_config); their images must exist.
        check_images_exist(self.client, config.registry_images())

    def _pki_config(self, config: ClusterConfig) -> PKIConfig:
        """Build the PKI configuration."""
        return PKIConfig(
            apiserver_hostnames=[self.container_name("kube-apiserver")],
            service_cluster_ip=str(ipaddress.ip_network(config.service_cidr)[1]),
            cluster_domain=config.cluster_domain,
            etcd_hostnames=[self.container_name("etcd")],
            extra_apiserver_sans=[config.node_endpoint_ip, *config.extra_apiserver_sans],
            konnectivity_sans=[self.container_name("konnectivity-server"), config.node_endpoint_ip],
        )

    def _load_or_generate_pki(
        self, pki_config: PKIConfig
    ) -> tuple[dict[str, bytes], dict[str, bytes]]:
        """Load the PKI from its volume, or generate and store it."""
        files = self.read_pki()
        if files is not None:
            return self._stored_pki(files)

        log.info("generating PKI")
        material = generate_cluster_pki(pki_config)
        konnectivity = self.container_name("konnectivity-server")
        kubeconfigs = generate_cluster_kubeconfigs(
            material, internal_server=self.internal_server, external_server=self.local_server
        )
        egress = generate_egress_selector_config(
            server_url=f"https://{konnectivity}:{KONNECTIVITY_SERVER_PORT}"
        )
        self._write_pki(
            {f"pki/{path}": pem for path, pem in material.items()}
            | kubeconfigs
            | {EGRESS_CONFIG: egress}
        )
        return material, kubeconfigs

    def _stored_pki(
        self, files: dict[str, bytes]
    ) -> tuple[dict[str, bytes], dict[str, bytes]]:
        """Split the PKI volume files into certificates and kubeconfigs."""
        missing = [path for path in self._required_pki_files() if path not in files]
        if missing:
            raise RuntimeError(
                f"volume {self.pki_volume} is incomplete (missing {', '.join(missing)}): "
                f"delete the cluster with `kuberd delete {self.name}` and create it again"
            )
        material = {p.removeprefix("pki/"): c for p, c in files.items() if p.startswith("pki/")}
        kubeconfigs = {p: c for p, c in files.items() if p.endswith(".conf")}
        return material, kubeconfigs

    def _create_control_plane(self) -> None:
        """Create and start the control plane containers."""
        if self._network() is None:
            self.client.networks.create(self.network_name, driver="bridge", labels=self.labels)
        self._ensure_volume(self.etcd_data_volume)
        for container in self.containers[: len(COMPONENTS)]:
            if not container.exists():
                container.create()
        self._start_control_plane()

    def _apply_phases(
        self, config: ClusterConfig, pki_config: PKIConfig, ca_cert_pem: bytes, super_admin: bytes
    ) -> None:
        """Apply the kubeadm phases."""
        for manifest in (
            generate_kubernetes_endpoints(ip=config.node_endpoint_ip, port=config.ports.api),
            generate_cluster_admins_rbac(),
            generate_upload_config(
                pki_config,
                cluster_name=self.name,
                versions=config.versions,
                control_plane_endpoint=self.node_endpoint,
                service_subnet=config.service_cidr,
            ),
            generate_bootstrap_token_phase(ca_cert_pem=ca_cert_pem, server=self.node_server),
            generate_addons(
                pki_config,
                versions=config.versions,
                control_plane_endpoint=self.node_endpoint,
                service_subnet=config.service_cidr,
            ),
            generate_konnectivity_agent(
                image=config.versions.konnectivity_agent_image,
                server_host=config.node_endpoint_ip,
                server_port=config.ports.konnectivity,
            ),
        ):
            try:
                self._apply_manifests(manifest, super_admin)
            except RuntimeError as e:
                diagnostics = self._diagnostics()
                if diagnostics:
                    raise RuntimeError(f"{e}\n{diagnostics}") from None
                raise

    def _required_pki_files(self) -> list[str]:
        """List the files required in the PKI volume."""
        required = list(CREATE_PKI_FILES)
        for container in self.containers[: len(COMPONENTS)]:
            for path in files_in_command(container.command or []):
                if path not in required:
                    required.append(path)
        return required

    def _diagnostics(self) -> str:
        """Collect the logs of the control plane containers that are not running."""
        lines = []
        for container in self.containers[: len(COMPONENTS)]:
            if container.exists() and not container.is_running():
                tail = container.logs().strip().splitlines()[-5:]
                lines.append(f"{container.name} is {container.status()}:")
                lines += [f"  {line}" for line in tail]
        return "\n".join(lines)

    def _start_control_plane(self) -> None:
        """Start the control plane containers."""
        for container in self.containers[: len(COMPONENTS)]:
            if not container.is_running():
                container.start()

    def _create_toolbox(self, admin_kubeconfig: bytes) -> None:
        """Create and start the toolbox container."""
        toolbox = self.container(TOOLBOX)
        if not toolbox.exists():
            versions = self._require_config().versions
            build_toolbox_image(self.client, versions.toolbox_image, versions.kubernetes)
            toolbox.create()
        toolbox.put_files(
            {
                "etc/kubernetes/admin.conf": (admin_kubeconfig, 0o600),
                "root/.kube/config": (admin_kubeconfig, 0o600),
            }
        )
        if not toolbox.is_running():
            toolbox.start()

    def start(self) -> None:
        """Start the cluster containers."""
        self._check_owner()
        missing = [c.name for c in self.containers if not c.exists()]
        if missing:
            raise RuntimeError(
                f"cluster {self.name!r} is incomplete (missing {', '.join(missing)}): "
                "run `kuberd create` to complete it"
            )
        dead = [c.name for c in self.containers if c.status() == "dead"]
        if dead:
            raise RuntimeError(
                f"containers {', '.join(dead)} are dead and cannot be started: "
                f"recreate the cluster with `kuberd delete {self.name}` and `kuberd create`"
            )
        for container in self.containers:
            status = container.status()
            if status == "paused":
                container.unpause()
            elif status in STOPPED_STATES:
                container.start()
            # "running" and "restarting" (Docker restarts it) are left alone.

    def stop(self, timeout: int = 10) -> None:
        """Stop the cluster containers."""
        self._check_owner()
        for container in reversed(self.containers):
            if container.exists() and container.status() not in STOPPED_STATES:
                container.stop(timeout=timeout)

    def delete(self) -> list[str]:
        """Delete the cluster containers, volumes and network; return the ones left in place."""
        kept = []
        # Containers first: volumes and the network cannot go while in use.
        for kind, name, resource in sorted(self._resources(), key=lambda r: r[0] != "container"):
            if resource is None:
                continue
            if not owned_by(resource, self.name):
                kept.append(f"{kind} {name}")
            elif kind == "container":
                resource.remove(force=True)
            else:
                resource.remove()
        return kept

    # --- kubectl ---------------------------------------------------------

    def _apply_manifests(self, manifest: bytes, kubeconfig: bytes, *, timeout: int = 120) -> None:
        """Apply a manifest to the cluster with kubectl."""
        kubectl = Container(
            self.container_name("kubectl"),
            image=self._require_config().versions.kubernetes_image("kubectl"),
            command=[
                "apply",
                "--request-timeout=30s",
                "--kubeconfig=/kuberd/kubeconfig",
                f"--server={self.internal_server}",
                "-f",
                "/kuberd/manifest.yaml",
            ],
            network=self.network_name,
            labels=self.labels,
            client=self.client,
        )
        deadline = time.monotonic() + timeout
        while True:
            if kubectl.exists():
                kubectl.delete(force=True)
            kubectl.create()
            try:
                kubectl.put_files(
                    {
                        "kuberd/kubeconfig": (kubeconfig, 0o600),
                        "kuberd/manifest.yaml": (manifest, 0o644),
                    }
                )
                kubectl.start()
                exit_code = kubectl.wait()
                logs = kubectl.logs()
            finally:
                try:
                    kubectl.delete(force=True)
                except DockerException as e:
                    log.warning("could not remove %s: %s", kubectl.name, e)

            if exit_code == 0:
                return
            if is_permanent_kubectl_error(logs) or time.monotonic() >= deadline:
                raise RuntimeError(f"kubectl apply failed on cluster {self.name!r}:\n{logs}")
            time.sleep(3)


def list_clusters(client: docker.DockerClient) -> dict[str, dict[str, str]]:
    """List the clusters and the state of their containers."""
    selector = {"label": LABEL}
    clusters: dict[str, dict[str, str]] = {}
    resources = [*client.volumes.list(filters=selector), *client.networks.list(filters=selector)]
    for resource in resources:
        clusters.setdefault(resource.attrs["Labels"][LABEL], {})
    for container in client.containers.list(all=True, filters=selector):
        clusters.setdefault(container.labels[LABEL], {})[container.name] = container.status
    return clusters
