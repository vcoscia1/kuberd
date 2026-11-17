import datetime
import re

# --- versions and images -----------------------------------------------------

IMAGE_REPOSITORY = "registry.k8s.io"
# Defaults, overridable per cluster (configuration file or `kuberd create` flags).
DEFAULT_KUBERNETES_VERSION = "v1.35.0"
DEFAULT_ETCD_VERSION = "3.6.6-0"
DEFAULT_COREDNS_VERSION = "v1.13.1"
DEFAULT_KONNECTIVITY_VERSION = "v0.34.0"
# Oldest supported Kubernetes minor (1.35): kuberd relies on kubeadm v1beta4
# and on the 1.35 component flags.
MIN_KUBERNETES_MINOR = 35
KUBERNETES_VERSION_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")  # e.g. v1.35.0
ETCD_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(-\d+)?$")  # e.g. 3.6.6-0
V_SEMVER_RE = re.compile(r"^v\d+\.\d+\.\d+$")  # CoreDNS and konnectivity, e.g. v1.13.1
# Never-started helper used to read/write the PKI volume: any image works,
# so a tiny one that does not depend on the cluster versions.
PKI_HELPER_IMAGE = f"{IMAGE_REPOSITORY}/pause:3.10.1"

# --- paths (inside the containers, as on a kubeadm node) ---------------------

K8S_DIR = "/etc/kubernetes"
PKI_DIR = f"{K8S_DIR}/pki"
ETCD_DATA_DIR = "/var/lib/etcd"
STATIC_POD_PATH = f"{K8S_DIR}/manifests"
EGRESS_CONFIG = "egress-selector-configuration.yaml"  # in the PKI volume

# --- ports -------------------------------------------------------------------

API_PORT = 6443
KONNECTIVITY_SERVER_PORT = 8131  # API server -> konnectivity-server (HTTPConnect, mTLS)
KONNECTIVITY_AGENT_PORT = 8132  # agents -> konnectivity-server
KONNECTIVITY_ADMIN_PORT = 8133  # konnectivity server and agent admin endpoints
KONNECTIVITY_HEALTH_PORT = 8134  # konnectivity server and agent /healthz
HOST_PORT_SEARCH_START = 30000  # first host port suggested by check_host_ports
LOCAL_API_IP = "127.0.0.1"  # the API server is also published here for local use

# --- PKI ---------------------------------------------------------------------

CA_VALIDITY = datetime.timedelta(days=3650)
LEAF_VALIDITY = datetime.timedelta(days=365)
CLOCK_SKEW = datetime.timedelta(minutes=5)
SA_KEY_SIZE = 2048
LOOPBACK_SANS = ["localhost", "127.0.0.1", "::1"]

# Files an existing PKI volume must hold besides those the component commands
# reference (derived by Cluster._required_pki_files): what create() reads, and
# the konnectivity client cert named only inside the egress configuration.
CREATE_PKI_FILES = [
    "pki/ca.crt",
    "pki/admin.crt",
    "pki/admin.key",
    "super-admin.conf",
    "pki/konnectivity/client.crt",
    "pki/konnectivity/client.key",
]

# --- Kubernetes identities and RBAC ------------------------------------------

RBAC = "rbac.authorization.k8s.io"
CLUSTER_ADMINS_GROUP = "kubeadm:cluster-admins"
MASTERS_GROUP = "system:masters"
NODES_GROUP = "system:nodes"
BOOTSTRAP_TOKEN_GROUP = "system:bootstrappers:kubeadm:default-node-token"
# The server accepts only agents running as this ServiceAccount (kube-system)
# with a token for this audience: both sides must use the same values.
KONNECTIVITY_AGENT_SA = "konnectivity-agent"
KONNECTIVITY_AUDIENCE = "system:konnectivity-server"
KONNECTIVITY_USER = "system:konnectivity-server"
# Cluster CA bundle mounted into every pod together with its ServiceAccount token.
SA_CA_CERT = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

# --- cluster containers ------------------------------------------------------

LABEL = "kuberd.cluster"  # on every container, volume and network of a cluster
# Start order matters: etcd first, then the API server, then its clients.
COMPONENTS = [
    "etcd",
    "kube-apiserver",
    "konnectivity-server",
    "kube-controller-manager",
    "kube-scheduler",
]
TOOLBOX = "toolbox"
# Short-lived helpers, never part of Cluster.containers.
HELPERS = ["kubectl", "pki-helper"]
# Docker states of a container that is not running and not about to run.
STOPPED_STATES = {"created", "exited", "dead"}
# Docker restarts a cluster container that exits on its own (there is no
# kubelet), but not one stopped with `kuberd stop`.
RESTART_POLICY = "unless-stopped"

# --- configuration file ------------------------------------------------------

API_VERSION = "kuberd/v1alpha1"
KIND = "Cluster"
# Used in container, volume and network names, and container hostnames: Docker
# allows 64 bytes and the longest suffix is "-kube-controller-manager" (24).
NAME_MAX = 40
NAME_RE = re.compile(rf"^[a-z0-9]([a-z0-9-]{{0,{NAME_MAX - 2}}}[a-z0-9])?$")
# The cluster network is named after the cluster: Docker's own networks are off limits.
RESERVED_NAMES = {"bridge", "host", "none"}
DNS_LABEL = r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
DNS_NAME_RE = re.compile(rf"^{DNS_LABEL}(\.{DNS_LABEL})*$")
# YAML key -> (ClusterConfig attribute, "ports."/"versions." for the grouped ones,
# expected type). The YAML file itself stays flat.
CONFIG_FIELDS = {
    "name": ("name", str),
    "nodeEndpointIP": ("node_endpoint_ip", str),
    "apiPort": ("ports.api", int),
    "konnectivityPort": ("ports.konnectivity", int),
    "serviceCIDR": ("service_cidr", str),
    "clusterDomain": ("cluster_domain", str),
    "extraAPIServerSANs": ("extra_apiserver_sans", list),
    "kubernetesVersion": ("versions.kubernetes", str),
    "etcdVersion": ("versions.etcd", str),
    "corednsVersion": ("versions.coredns", str),
    "konnectivityVersion": ("versions.konnectivity", str),
}

# --- templates ---------------------------------------------------------------

# CoreDNS Corefile as generated by kubeadm ({domain}: cluster domain).
COREFILE = """\
.:53 {{
    errors
    health {{
       lameduck 5s
    }}
    ready
    kubernetes {domain} in-addr.arpa ip6.arpa {{
       pods insecure
       fallthrough in-addr.arpa ip6.arpa
       ttl 30
    }}
    prometheus :9153
    forward . /etc/resolv.conf {{
       max_concurrent 1000
    }}
    cache 30 {{
       disable success {domain}
       disable denial {domain}
    }}
    loop
    reload
    loadbalance
}}
"""

# kubectl + kubeadm from dl.k8s.io, checksums verified; arch from the base image.
TOOLBOX_DOCKERFILE = """\
FROM debian:bookworm-slim
ARG VERSION
RUN apt-get update \\
 && apt-get install -y --no-install-recommends ca-certificates curl \\
 && rm -rf /var/lib/apt/lists/* \\
 && arch="$(dpkg --print-architecture)" \\
 && cd /usr/local/bin \\
 && for bin in kubectl kubeadm; do \\
      url="https://dl.k8s.io/release/${VERSION}/bin/linux/${arch}/${bin}"; \\
      curl -fsSLo "${bin}" "${url}" \\
      && echo "$(curl -fsSL "${url}.sha256")  ${bin}" | sha256sum -c - \\
      && chmod 0755 "${bin}" || exit 1; \\
    done
CMD ["sleep", "infinity"]
"""
