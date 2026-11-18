from dataclasses import dataclass

from kuberd.constants import (
    DEFAULT_COREDNS_VERSION,
    DEFAULT_ETCD_VERSION,
    DEFAULT_KONNECTIVITY_VERSION,
    DEFAULT_KUBERNETES_VERSION,
    IMAGE_REPOSITORY,
)


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
