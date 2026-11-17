"""kuberd cluster configuration file (YAML).

    apiVersion: kuberd/v1alpha1
    kind: Cluster
    name: kuberd
    nodeEndpointIP: 192.168.1.80   # host IP the nodes (external VMs) reach
    apiPort: 30000                 # published API port (nodes + 127.0.0.1)
    konnectivityPort: 30001        # published konnectivity agent port
    serviceCIDR: 10.96.0.0/12
    clusterDomain: cluster.local
    extraAPIServerSANs: []
    kubernetesVersion: v1.35.0     
    etcdVersion: 3.6.6-0
    corednsVersion: v1.13.1
    konnectivityVersion: v0.34.0
"""

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from kuberd.constants import (
    API_VERSION,
    KIND,
    NAME_MAX,
    NAME_RE,
    RESERVED_NAMES,
    CONFIG_FIELDS,
    DEFAULT_COREDNS_VERSION,
    DEFAULT_ETCD_VERSION,
    DEFAULT_KONNECTIVITY_VERSION,
    DEFAULT_KUBERNETES_VERSION,
    ETCD_VERSION_RE,
    IMAGE_REPOSITORY,
    KUBERNETES_VERSION_RE,
    MIN_KUBERNETES_MINOR,
    PKI_HELPER_IMAGE,
    V_SEMVER_RE,
)
from kuberd.utils import (
    valid_san,
    valid_dns_name,
)


class ConfigError(ValueError):
    """Error in a cluster configuration."""


@dataclass
class HostPorts:
    """Host ports published by a cluster."""

    api: int = 30000  # API server, on nodeEndpointIP and 127.0.0.1
    konnectivity: int = 30001  # konnectivity agents, on nodeEndpointIP


@dataclass
class Versions:
    """Versions of the cluster components."""

    kubernetes: str = DEFAULT_KUBERNETES_VERSION
    etcd: str = DEFAULT_ETCD_VERSION
    coredns: str = DEFAULT_COREDNS_VERSION
    konnectivity: str = DEFAULT_KONNECTIVITY_VERSION

    def kubernetes_image(self, component: str) -> str:
        """Image of a Kubernetes component."""
        return f"{IMAGE_REPOSITORY}/{component}:{self.kubernetes}"

    @property
    def etcd_image(self) -> str:
        """etcd image."""
        return f"{IMAGE_REPOSITORY}/etcd:{self.etcd}"

    @property
    def coredns_image(self) -> str:
        """CoreDNS image."""
        return f"{IMAGE_REPOSITORY}/coredns/coredns:{self.coredns}"

    @property
    def konnectivity_server_image(self) -> str:
        """konnectivity-server image."""
        return f"{IMAGE_REPOSITORY}/kas-network-proxy/proxy-server:{self.konnectivity}"

    @property
    def konnectivity_agent_image(self) -> str:
        """konnectivity-agent image."""
        return f"{IMAGE_REPOSITORY}/kas-network-proxy/proxy-agent:{self.konnectivity}"

    @property
    def toolbox_image(self) -> str:
        """Toolbox image."""
        return f"kuberd/toolbox:{self.kubernetes}"


@dataclass
class ClusterConfig:
    """Configuration of a cluster."""
    name: str
    node_endpoint_ip: str
    ports: HostPorts = field(default_factory=HostPorts)
    service_cidr: str = "10.96.0.0/12"
    cluster_domain: str = "cluster.local"
    extra_apiserver_sans: list[str] = field(default_factory=list)
    versions: Versions = field(default_factory=Versions)

    def registry_images(self) -> list[str]:
        """List the images pulled from the registry."""
        v = self.versions
        components = (
            "kube-apiserver",
            "kube-controller-manager",
            "kube-scheduler",
            "kube-proxy",
            "kubectl",
        )
        return [
            PKI_HELPER_IMAGE,
            *(v.kubernetes_image(c) for c in components),
            v.etcd_image,
            v.coredns_image,
            v.konnectivity_server_image,
            v.konnectivity_agent_image,
        ]


def load_config(path: str | Path, overrides: dict | None = None) -> ClusterConfig:
    """Load and validate a cluster configuration file."""
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        raise ConfigError(f"{path}: {e}") from None
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: expected a YAML mapping")
    data.update({key: value for key, value in (overrides or {}).items() if value is not None})

    if data.pop("apiVersion", None) != API_VERSION or data.pop("kind", None) != KIND:
        raise ConfigError(f"{path}: expected apiVersion: {API_VERSION} and kind: {KIND}")
    unknown = sorted(set(data) - set(CONFIG_FIELDS))
    if unknown:
        raise ConfigError(f"{path}: unknown keys: {', '.join(unknown)}")
    missing = [key for key in ("name", "nodeEndpointIP") if key not in data]
    if missing:
        raise ConfigError(f"{path}: missing required keys: {', '.join(missing)}")

    values: dict = {"ports": {}, "versions": {}}
    for key, value in data.items():
        attr, expected = CONFIG_FIELDS[key]
        # bool is an int subclass: reject it explicitly for the ports.
        if not isinstance(value, expected) or isinstance(value, bool):
            raise ConfigError(f"{path}: {key} must be a {expected.__name__}")
        group, _, field_name = attr.rpartition(".")
        (values[group] if group else values)[field_name] = value
    config = ClusterConfig(
        **{k: v for k, v in values.items() if k not in ("ports", "versions")},
        ports=HostPorts(**values["ports"]),
        versions=Versions(**values["versions"]),
    )
    _validate(config, path)
    return config


def _validate_versions(config: ClusterConfig, path: str | Path) -> None:
    """Validate the component versions."""
    versions = config.versions
    match = KUBERNETES_VERSION_RE.match(versions.kubernetes)
    if not match:
        raise ConfigError(
            f"{path}: kubernetesVersion {versions.kubernetes!r} must look like "
            f"v1.{MIN_KUBERNETES_MINOR}.0 (vMAJOR.MINOR.PATCH)"
        )
    major, minor = int(match.group(1)), int(match.group(2))
    if major != 1 or minor < MIN_KUBERNETES_MINOR:
        raise ConfigError(
            f"{path}: kubernetesVersion {versions.kubernetes} is not supported: "
            f"use v1.{MIN_KUBERNETES_MINOR}.0 or a later 1.x release"
        )
    if not ETCD_VERSION_RE.match(versions.etcd):
        raise ConfigError(f"{path}: etcdVersion {versions.etcd!r} must look like 3.6.6-0")
    for key, value in (
        ("corednsVersion", versions.coredns),
        ("konnectivityVersion", versions.konnectivity),
    ):
        if not V_SEMVER_RE.match(value):
            raise ConfigError(f"{path}: {key} {value!r} must look like v1.2.3")


def _validate(config: ClusterConfig, path: str | Path) -> None:
    """Validate a cluster configuration."""
    if not NAME_RE.match(config.name):
        raise ConfigError(
            f"{path}: name must be lowercase letters, digits and '-', at most {NAME_MAX} characters"
        )
    if config.name in RESERVED_NAMES:
        raise ConfigError(f"{path}: name {config.name!r} is reserved by Docker")
    try:
        ipaddress.IPv4Address(config.node_endpoint_ip)
    except ValueError:
        raise ConfigError(f"{path}: nodeEndpointIP is not an IPv4 address") from None
    ports = (("apiPort", config.ports.api), ("konnectivityPort", config.ports.konnectivity))
    for key, port in ports:
        if not 1 <= port <= 65535:
            raise ConfigError(f"{path}: {key} must be between 1 and 65535")
    if config.ports.api == config.ports.konnectivity:
        raise ConfigError(f"{path}: apiPort and konnectivityPort must differ")
    try:
        network = ipaddress.IPv4Network(config.service_cidr)
    except ValueError:
        raise ConfigError(f"{path}: serviceCIDR is not a valid IPv4 network") from None
    if network.num_addresses < 16:
        raise ConfigError(f"{path}: serviceCIDR is too small")
    if not valid_dns_name(config.cluster_domain):
        raise ConfigError(f"{path}: clusterDomain {config.cluster_domain!r} is not a DNS name")
    _validate_versions(config, path)
    for san in config.extra_apiserver_sans:
        if not isinstance(san, str) or not valid_san(san):
            raise ConfigError(
                f"{path}: extraAPIServerSANs: {san!r} is not an IPv4 address or DNS name"
            )
