import base64
import datetime
import errno
import io
import ipaddress
import socket
from typing import NamedTuple

import docker
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from docker.errors import APIError, NotFound

from kuberd.constants import (
    K8S_DIR,
    PKI_DIR,
    ETCD_DATA_DIR,
    EGRESS_CONFIG,
    API_PORT,
    KONNECTIVITY_SERVER_PORT,
    KONNECTIVITY_AGENT_PORT,
    KONNECTIVITY_ADMIN_PORT,
    KONNECTIVITY_HEALTH_PORT,
    KONNECTIVITY_AGENT_SA,
    KONNECTIVITY_AUDIENCE,
    HOST_PORT_SEARCH_START,
    LEAF_VALIDITY,
    CLOCK_SKEW,
    RBAC,
    NODES_GROUP,
    BOOTSTRAP_TOKEN_GROUP,
    LABEL,
    DNS_NAME_RE,
    TOOLBOX_DOCKERFILE,
)


# --- X.509 -------------------------------------------------------------------


class KeyCert(NamedTuple):
    """Private key and certificate."""
    key: ec.EllipticCurvePrivateKey
    cert: x509.Certificate


def new_key() -> ec.EllipticCurvePrivateKey:
    """Generate an ECDSA P-256 private key."""
    return ec.generate_private_key(ec.SECP256R1())


def x509_name(common_name: str, organizations: list[str] | tuple[str, ...] = ()) -> x509.Name:
    """Build a certificate subject."""
    attrs = [x509.NameAttribute(NameOID.ORGANIZATION_NAME, o) for o in organizations]
    attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    return x509.Name(attrs)


def san_extension(entries: list[str]) -> x509.SubjectAlternativeName:
    """Build a SubjectAlternativeName extension."""
    names: list[x509.GeneralName] = []
    seen: set[str] = set()
    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue
        try:
            ip = ipaddress.ip_address(entry)
        except ValueError:
            key = entry.lower()
            name: x509.GeneralName = x509.DNSName(entry)
        else:
            key = str(ip)
            name = x509.IPAddress(ip)
        if key not in seen:
            seen.add(key)
            names.append(name)
    return x509.SubjectAlternativeName(names)


def key_usage(*, digital_signature: bool = False, cert_sign: bool = False) -> x509.KeyUsage:
    """Build a KeyUsage extension."""
    return x509.KeyUsage(
        digital_signature=digital_signature,
        content_commitment=False,
        key_encipherment=False,  # not applicable to ECDSA keys
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=cert_sign,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


def sign_leaf(
    ca: KeyCert,
    subject: x509.Name,
    usages: list[x509.ObjectIdentifier],
    sans: list[str] | None = None,
) -> KeyCert:
    """Generate a certificate signed by a CA."""
    key = new_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    not_after = min(now + LEAF_VALIDITY, ca.cert.not_valid_after_utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca.cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - CLOCK_SKEW)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(key_usage(digital_signature=True), critical=True)
        .add_extension(x509.ExtendedKeyUsage(usages), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.key.public_key()),
            critical=False,
        )
    )
    if sans:
        builder = builder.add_extension(san_extension(sans), critical=False)
    return KeyCert(key, builder.sign(ca.key, hashes.SHA256()))


# --- Kubernetes manifests ----------------------------------------------------


def b64(pem: bytes) -> str:
    """Encode bytes as base64."""
    return base64.b64encode(pem).decode("ascii")


def config_map(name: str, key: str, content: dict) -> dict:
    """Build a ConfigMap."""
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": "kube-system"},
        "data": {key: yaml.safe_dump(content, sort_keys=False)},
    }


def to_yaml(objects: list[dict]) -> bytes:
    """Serialize Kubernetes objects as a multi-document YAML."""
    return yaml.safe_dump_all(objects, sort_keys=False).encode("utf-8")


def cluster_role_binding(name: str, cluster_role: str, subjects: list[dict]) -> dict:
    """Build a ClusterRoleBinding."""
    return {
        "apiVersion": f"{RBAC}/v1",
        "kind": "ClusterRoleBinding",
        "metadata": {"name": name},
        "roleRef": {"apiGroup": RBAC, "kind": "ClusterRole", "name": cluster_role},
        "subjects": subjects,
    }


def rbac_group(name: str) -> dict:
    """Build an RBAC group subject."""
    return {"apiGroup": RBAC, "kind": "Group", "name": name}


def get_one_role(name: str, namespace: str, resource: str, resource_name: str) -> dict:
    """Build a Role that can read one resource."""
    return {
        "apiVersion": f"{RBAC}/v1",
        "kind": "Role",
        "metadata": {"name": name, "namespace": namespace},
        "rules": [
            {
                "apiGroups": [""],
                "resources": [resource],
                "resourceNames": [resource_name],
                "verbs": ["get"],
            }
        ],
    }


def role_binding(name: str, namespace: str, subjects: list[dict]) -> dict:
    """Build a RoleBinding."""
    return {
        "apiVersion": f"{RBAC}/v1",
        "kind": "RoleBinding",
        "metadata": {"name": name, "namespace": namespace},
        "roleRef": {"apiGroup": RBAC, "kind": "Role", "name": name},
        "subjects": subjects,
    }


def config_map_reader(role: str, config_map_name: str) -> list[dict]:
    """Build the Role and RoleBinding to read a ConfigMap."""
    return [
        get_one_role(role, "kube-system", "configmaps", config_map_name),
        role_binding(
            role, "kube-system", [rbac_group(BOOTSTRAP_TOKEN_GROUP), rbac_group(NODES_GROUP)]
        ),
    ]


# --- containers and host -----------------------------------------------------


def container_name(cluster: str, component: str) -> str:
    """Build the name of a cluster container."""
    return f"{cluster}-{component}"


def etcd_command(cluster: str) -> list[str]:
    """Build the etcd command line."""
    name = container_name(cluster, "etcd")
    return [
        "etcd",
        f"--name={name}",
        f"--data-dir={ETCD_DATA_DIR}",
        "--listen-client-urls=https://0.0.0.0:2379",
        f"--advertise-client-urls=https://{name}:2379",
        "--listen-peer-urls=https://0.0.0.0:2380",
        f"--initial-advertise-peer-urls=https://{name}:2380",
        f"--initial-cluster={name}=https://{name}:2380",
        "--initial-cluster-state=new",
        "--listen-metrics-urls=http://127.0.0.1:2381",
        "--client-cert-auth=true",
        f"--trusted-ca-file={PKI_DIR}/etcd/ca.crt",
        f"--cert-file={PKI_DIR}/etcd/server.crt",
        f"--key-file={PKI_DIR}/etcd/server.key",
        "--peer-client-cert-auth=true",
        f"--peer-trusted-ca-file={PKI_DIR}/etcd/ca.crt",
        f"--peer-cert-file={PKI_DIR}/etcd/peer.crt",
        f"--peer-key-file={PKI_DIR}/etcd/peer.key",
    ]


def apiserver_command(
    cluster: str, service_cidr: str, cluster_domain: str, advertise_address: str
) -> list[str]:
    """Build the kube-apiserver command line."""
    etcd = container_name(cluster, "etcd")
    return [
        "kube-apiserver",
        f"--secure-port={API_PORT}",
        f"--advertise-address={advertise_address}",
        # The host port differs from --secure-port, so the "kubernetes" Service
        # endpoint is managed by kuberd (kubeadm.generate_kubernetes_endpoints).
        "--endpoint-reconciler-type=none",
        "--allow-privileged=true",
        f"--egress-selector-config-file={K8S_DIR}/{EGRESS_CONFIG}",
        "--enable-bootstrap-token-auth=true",
        "--authorization-mode=Node,RBAC",
        "--enable-admission-plugins=NodeRestriction",
        f"--client-ca-file={PKI_DIR}/ca.crt",
        f"--tls-cert-file={PKI_DIR}/apiserver.crt",
        f"--tls-private-key-file={PKI_DIR}/apiserver.key",
        f"--etcd-servers=https://{etcd}:2379",
        f"--etcd-cafile={PKI_DIR}/etcd/ca.crt",
        f"--etcd-certfile={PKI_DIR}/apiserver-etcd-client.crt",
        f"--etcd-keyfile={PKI_DIR}/apiserver-etcd-client.key",
        f"--kubelet-client-certificate={PKI_DIR}/apiserver-kubelet-client.crt",
        f"--kubelet-client-key={PKI_DIR}/apiserver-kubelet-client.key",
        "--kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname",
        f"--proxy-client-cert-file={PKI_DIR}/front-proxy-client.crt",
        f"--proxy-client-key-file={PKI_DIR}/front-proxy-client.key",
        f"--requestheader-client-ca-file={PKI_DIR}/front-proxy-ca.crt",
        "--requestheader-allowed-names=front-proxy-client",
        "--requestheader-extra-headers-prefix=X-Remote-Extra-",
        "--requestheader-group-headers=X-Remote-Group",
        "--requestheader-username-headers=X-Remote-User",
        f"--service-account-issuer=https://kubernetes.default.svc.{cluster_domain}",
        f"--service-account-key-file={PKI_DIR}/sa.pub",
        f"--service-account-signing-key-file={PKI_DIR}/sa.key",
        f"--service-cluster-ip-range={service_cidr}",
    ]


def controller_manager_command(cluster: str) -> list[str]:
    """Build the kube-controller-manager command line."""
    conf = f"{K8S_DIR}/controller-manager.conf"
    return [
        "kube-controller-manager",
        "--bind-address=127.0.0.1",
        f"--kubeconfig={conf}",
        f"--authentication-kubeconfig={conf}",
        f"--authorization-kubeconfig={conf}",
        f"--client-ca-file={PKI_DIR}/ca.crt",
        f"--requestheader-client-ca-file={PKI_DIR}/front-proxy-ca.crt",
        f"--cluster-name={cluster}",
        f"--cluster-signing-cert-file={PKI_DIR}/ca.crt",
        f"--cluster-signing-key-file={PKI_DIR}/ca.key",
        f"--root-ca-file={PKI_DIR}/ca.crt",
        f"--service-account-private-key-file={PKI_DIR}/sa.key",
        "--use-service-account-credentials=true",
        "--controllers=*,bootstrapsigner,tokencleaner",
        "--leader-elect=true",
    ]


def konnectivity_command() -> list[str]:
    """Build the konnectivity-server command line."""
    return [
        "--logtostderr=true",
        "--mode=http-connect",  # kube-apiserver allows GRPC only over UDS
        "--uds-name=",
        f"--server-port={KONNECTIVITY_SERVER_PORT}",
        f"--server-cert={PKI_DIR}/konnectivity/server.crt",
        f"--server-key={PKI_DIR}/konnectivity/server.key",
        f"--server-ca-cert={PKI_DIR}/konnectivity/ca.crt",
        f"--agent-port={KONNECTIVITY_AGENT_PORT}",
        f"--cluster-cert={PKI_DIR}/konnectivity/cluster.crt",
        f"--cluster-key={PKI_DIR}/konnectivity/cluster.key",
        f"--admin-port={KONNECTIVITY_ADMIN_PORT}",
        f"--health-port={KONNECTIVITY_HEALTH_PORT}",
        f"--kubeconfig={K8S_DIR}/konnectivity-server.conf",
        "--agent-namespace=kube-system",
        f"--agent-service-account={KONNECTIVITY_AGENT_SA}",
        f"--authentication-audience={KONNECTIVITY_AUDIENCE}",
    ]


def scheduler_command() -> list[str]:
    """Build the kube-scheduler command line."""
    conf = f"{K8S_DIR}/scheduler.conf"
    return [
        "kube-scheduler",
        "--bind-address=127.0.0.1",
        f"--kubeconfig={conf}",
        f"--authentication-kubeconfig={conf}",
        f"--authorization-kubeconfig={conf}",
        "--leader-elect=true",
    ]


def port_free(ip: str, port: int) -> bool:
    """Check whether a port is free on an IP of the host."""
    with socket.socket(socket.AF_INET) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((ip, port))
        except OSError as e:
            if e.errno == errno.EADDRINUSE:
                return False
            raise
    return True


def check_ip_on_host(ip: str) -> None:
    """Check that an IP belongs to the host."""
    with socket.socket(socket.AF_INET) as s:
        try:
            s.bind((ip, 0))
        except OSError as e:
            if e.errno == errno.EADDRNOTAVAIL:
                raise RuntimeError(f"{ip} is not an address of this host") from None
            raise


def check_host_ports(bindings: list[tuple[str, int]]) -> None:
    """Check that the host ports are free."""
    for ip in {ip for ip, _ in bindings}:
        check_ip_on_host(ip)
    requested = {port for _, port in bindings}
    busy = [(ip, port) for ip, port in bindings if not port_free(ip, port)]
    if not busy:
        return
    lines = []
    for ip, port in busy:
        candidate = HOST_PORT_SEARCH_START
        while candidate in requested or not port_free(ip, candidate):
            candidate += 1
            if candidate > 65535:
                raise RuntimeError(f"no free port >= {HOST_PORT_SEARCH_START} on {ip}")
        lines.append(f"  {ip}:{port} is in use; first free port: {candidate}")
    raise RuntimeError("host ports not available:\n" + "\n".join(lines))


def check_images_exist(client: docker.DockerClient, images: list[str]) -> None:
    """Check that the images exist."""
    missing, unreachable = [], []
    for image in images:
        try:
            client.images.get(image)
            continue
        except NotFound:
            pass
        try:
            client.images.get_registry_data(image)
        except NotFound:
            missing.append(image)
        except APIError as e:
            unreachable.append(f"{image} ({e.explanation or e})")
    errors = []
    if missing:
        errors.append(f"images not found on the registry: {', '.join(missing)}")
    if unreachable:
        errors.append("cannot reach the registry to check: " + "; ".join(unreachable))
    if errors:
        raise RuntimeError("\n".join(errors))


def build_toolbox_image(client: docker.DockerClient, image: str, kubernetes_version: str) -> None:
    """Build the toolbox image."""
    try:
        client.images.get(image)
        return
    except NotFound:
        pass
    client.images.build(
        fileobj=io.BytesIO(TOOLBOX_DOCKERFILE.encode()),
        tag=image,
        buildargs={"VERSION": kubernetes_version},
        rm=True,
        pull=True,
    )


def files_in_command(command: list[str]) -> list[str]:
    """List the /etc/kubernetes files used by a command line."""
    prefix = f"{K8S_DIR}/"
    return [
        arg.split("=", 1)[1].removeprefix(prefix)
        for arg in command
        if "=" in arg and arg.split("=", 1)[1].startswith(prefix)
    ]


def is_permanent_kubectl_error(output: str) -> bool:
    """Check whether a kubectl error cannot be fixed by retrying."""
    return any(
        marker in output
        for marker in (
            "is invalid",
            "ValidationError",
            "unknown field",
            "field is immutable",
            "error parsing",
            "error converting YAML",
        )
    )


def owned_by(resource, cluster: str) -> bool:
    """Check whether a Docker resource belongs to a cluster."""
    # Volumes and networks keep labels in "Labels", containers in "Config.Labels".
    labels = resource.attrs.get("Labels") or resource.attrs.get("Config", {}).get("Labels")
    return (labels or {}).get(LABEL) == cluster


def file_mode(path: str) -> int:
    """Return the file mode of a PKI file."""
    return 0o644 if path.endswith((".crt", ".pub")) else 0o600


# --- validation --------------------------------------------------------------


def valid_san(san: str) -> bool:
    """Check whether a string is a valid SAN."""
    try:
        ipaddress.IPv4Address(san)
        return True
    except ValueError:
        # A DNS name cannot contain ':', so IPv6 addresses are rejected here too.
        return valid_dns_name(san)


def valid_dns_name(name: str) -> bool:
    """Check whether a string is a valid DNS name."""
    return len(name) <= 253 and DNS_NAME_RE.match(name) is not None
