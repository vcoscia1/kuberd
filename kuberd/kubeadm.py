import ipaddress
from dataclasses import dataclass, field

import yaml

from kuberd import pki
from kuberd.constants import (
    CA_VALIDITY,
    LEAF_VALIDITY,
    IMAGE_REPOSITORY,
    PKI_DIR,
    ETCD_DATA_DIR,
    STATIC_POD_PATH,
    LOOPBACK_SANS,
    RBAC,
    CLUSTER_ADMINS_GROUP,
    MASTERS_GROUP,
    NODES_GROUP,
    BOOTSTRAP_TOKEN_GROUP,
    KONNECTIVITY_AUDIENCE,
    KONNECTIVITY_AGENT_SA,
    SA_CA_CERT,
    KONNECTIVITY_ADMIN_PORT,
    KONNECTIVITY_HEALTH_PORT,
    KONNECTIVITY_USER,
    COREFILE,
)
from kuberd.utils import (
    KeyCert,
    b64,
    config_map,
    config_map_reader,
    to_yaml,
    cluster_role_binding,
    rbac_group,
    get_one_role,
    role_binding,
)
from kuberd.versions import Versions


@dataclass
class PKIConfig:
    """Names and addresses included in the certificates."""

    apiserver_hostnames: list[str] = field(default_factory=list)
    service_cluster_ip: str | None = None  # e.g. "10.96.0.1"
    cluster_domain: str | None = None  # e.g. "cluster.local"
    etcd_hostnames: list[str] = field(default_factory=list)
    extra_apiserver_sans: list[str] = field(default_factory=list)
    # Names/IPs of konnectivity-server: used by the API server (port 8131)
    # and by the agents (port 8132).
    konnectivity_sans: list[str] = field(default_factory=list)


# --- SANs --------------------------------------------------------------------


def apiserver_sans(config: PKIConfig) -> list[str]:
    """List the SANs of the API server certificate."""
    sans = list(config.apiserver_hostnames)
    if config.service_cluster_ip:
        sans.append(config.service_cluster_ip)
    if config.cluster_domain:
        sans += [
            "kubernetes",
            "kubernetes.default",
            "kubernetes.default.svc",
            f"kubernetes.default.svc.{config.cluster_domain}",
        ]
    return [*sans, *LOOPBACK_SANS, *config.extra_apiserver_sans]


def etcd_sans(config: PKIConfig) -> list[str]:
    """List the SANs of the etcd certificates."""
    return [*config.etcd_hostnames, *LOOPBACK_SANS]


# --- PKI ---------------------------------------------------------------------


def generate_cluster_ca() -> dict[str, KeyCert]:
    """Generate the cluster CAs."""
    return {
        "ca": pki.generate_ca("kubernetes"),
        "etcd/ca": pki.generate_ca("etcd-ca"),
        "front-proxy-ca": pki.generate_ca("front-proxy-ca"),
        "konnectivity/ca": pki.generate_ca("konnectivity-ca"),
    }


def generate_cluster_certs(config: PKIConfig, cas: dict[str, KeyCert]) -> dict[str, KeyCert]:
    """Generate the control plane certificates."""
    k8s_ca, etcd_ca, front_proxy_ca = cas["ca"], cas["etcd/ca"], cas["front-proxy-ca"]
    konnectivity_ca = cas["konnectivity/ca"]
    api_sans = apiserver_sans(config)
    etcd_names = etcd_sans(config)

    certs = {
        "apiserver": pki.generate_server_cert(k8s_ca, "kube-apiserver", api_sans),
        "apiserver-kubelet-client": pki.generate_client_cert(
            k8s_ca, "kube-apiserver-kubelet-client", [CLUSTER_ADMINS_GROUP]
        ),
        "admin": pki.generate_client_cert(k8s_ca, "kubernetes-admin", [CLUSTER_ADMINS_GROUP]),
        "super-admin": pki.generate_client_cert(
            k8s_ca, "kubernetes-super-admin", [MASTERS_GROUP]
        ),
        "controller-manager": pki.generate_client_cert(k8s_ca, "system:kube-controller-manager"),
        "scheduler": pki.generate_client_cert(k8s_ca, "system:kube-scheduler"),
        # Single-node etcd: server and peer share SANs and both need clientAuth.
        "etcd/server": pki.generate_server_cert(
            etcd_ca, "kube-etcd", etcd_names, client_auth=True
        ),
        "etcd/peer": pki.generate_server_cert(
            etcd_ca, "kube-etcd-peer", etcd_names, client_auth=True
        ),
        "etcd/healthcheck-client": pki.generate_client_cert(
            etcd_ca, "kube-etcd-healthcheck-client"
        ),
        "apiserver-etcd-client": pki.generate_client_cert(etcd_ca, "kube-apiserver-etcd-client"),
        "front-proxy-client": pki.generate_client_cert(front_proxy_ca, "front-proxy-client"),
        # konnectivity: API server <-> server mTLS (konnectivity CA) ...
        "konnectivity/server": pki.generate_server_cert(
            konnectivity_ca, "konnectivity-server", config.konnectivity_sans
        ),
        "konnectivity/client": pki.generate_client_cert(
            konnectivity_ca, "kube-apiserver-konnectivity-client"
        ),
        # ... agent-facing TLS, verified by agents with the cluster CA ...
        "konnectivity/cluster": pki.generate_server_cert(
            k8s_ca, "konnectivity-server", config.konnectivity_sans
        ),
        # ... and the server's own API identity (agent TokenReviews).
        "konnectivity-server": pki.generate_client_cert(k8s_ca, KONNECTIVITY_USER),
    }
    return certs


def generate_service_account_keys() -> dict[str, bytes]:
    """Generate the ServiceAccount signing key pair."""
    key = pki.generate_service_account_key()
    return {"sa.key": pki.key_to_pem(key), "sa.pub": pki.public_key_to_pem(key)}


def generate_cluster_pki(config: PKIConfig) -> dict[str, bytes]:
    """Generate the cluster PKI."""
    cas = generate_cluster_ca()
    certs = generate_cluster_certs(config, cas)

    pem: dict[str, bytes] = {}
    for path, (key, cert) in {**cas, **certs}.items():
        pem[f"{path}.crt"] = pki.cert_to_pem(cert)
        pem[f"{path}.key"] = pki.key_to_pem(key)
    pem.update(generate_service_account_keys())
    return pem


# --- Kubeconfig --------------------------------------------------------------


def generate_kubeconfig(
    *,
    server: str,
    ca_cert_pem: bytes,
    user: str,
    client_cert_pem: bytes,
    client_key_pem: bytes,
) -> bytes:
    """Generate a kubeconfig."""
    cluster_name = "kubernetes"
    context = f"{user}@{cluster_name}"
    config = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [
            {
                "name": cluster_name,
                "cluster": {
                    "certificate-authority-data": b64(ca_cert_pem),
                    "server": server,
                },
            }
        ],
        "contexts": [
            {
                "name": context,
                "context": {"cluster": cluster_name, "user": user},
            }
        ],
        "current-context": context,
        "preferences": {},
        "users": [
            {
                "name": user,
                "user": {
                    "client-certificate-data": b64(client_cert_pem),
                    "client-key-data": b64(client_key_pem),
                },
            }
        ],
    }
    return yaml.safe_dump(config, sort_keys=False).encode("utf-8")


def generate_cluster_kubeconfigs(
    pki_pem: dict[str, bytes], *, internal_server: str, external_server: str
) -> dict[str, bytes]:
    """Generate the control plane kubeconfigs."""
    # kubeconfig name -> (server, user name, PKI path of the client cert/key)
    specs = {
        "admin.conf": (external_server, "kubernetes-admin", "admin"),
        "super-admin.conf": (external_server, "kubernetes-super-admin", "super-admin"),
        "controller-manager.conf": (
            internal_server,
            "system:kube-controller-manager",
            "controller-manager",
        ),
        "scheduler.conf": (internal_server, "system:kube-scheduler", "scheduler"),
        "konnectivity-server.conf": (internal_server, KONNECTIVITY_USER, "konnectivity-server"),
    }

    return {
        name: generate_kubeconfig(
            server=server,
            ca_cert_pem=pki_pem["ca.crt"],
            user=user,
            client_cert_pem=pki_pem[f"{path}.crt"],
            client_key_pem=pki_pem[f"{path}.key"],
        )
        for name, (server, user, path) in specs.items()
    }


# --- upload-config -----------------------------------------------------------


def generate_upload_config_kubeadm(
    config: PKIConfig,
    *,
    cluster_name: str,
    versions: Versions,
    control_plane_endpoint: str,
    service_subnet: str,
) -> list[dict]:
    """Generate the kubeadm-config ConfigMap and its RBAC."""
    cluster_configuration = {
        "apiVersion": "kubeadm.k8s.io/v1beta4",
        "kind": "ClusterConfiguration",
        "clusterName": cluster_name,
        "kubernetesVersion": versions.kubernetes,
        "controlPlaneEndpoint": control_plane_endpoint,
        "certificatesDir": PKI_DIR,
        "imageRepository": IMAGE_REPOSITORY,
        "encryptionAlgorithm": "ECDSA-P256",
        "caCertificateValidityPeriod": f"{CA_VALIDITY.days * 24}h0m0s",
        "certificateValidityPeriod": f"{LEAF_VALIDITY.days * 24}h0m0s",
        "networking": {"serviceSubnet": service_subnet},
        "etcd": {"local": {"dataDir": ETCD_DATA_DIR, "imageTag": versions.etcd}},
        "dns": {"imageTag": versions.coredns},
    }
    if config.cluster_domain:
        cluster_configuration["networking"]["dnsDomain"] = config.cluster_domain
    if config.extra_apiserver_sans:
        cluster_configuration["apiServer"] = {"certSANs": list(config.extra_apiserver_sans)}

    return [
        config_map("kubeadm-config", "ClusterConfiguration", cluster_configuration),
        *config_map_reader("kubeadm:nodes-kubeadm-config", "kubeadm-config"),
    ]


def generate_upload_config_kubelet(config: PKIConfig, *, service_subnet: str) -> list[dict]:
    """Generate the kubelet-config ConfigMap and its RBAC."""
    kubelet_configuration = {
        "apiVersion": "kubelet.config.k8s.io/v1beta1",
        "kind": "KubeletConfiguration",
        "authentication": {
            "anonymous": {"enabled": False},
            "webhook": {"enabled": True, "cacheTTL": "0s"},
            "x509": {"clientCAFile": f"{PKI_DIR}/ca.crt"},
        },
        "authorization": {
            "mode": "Webhook",
            "webhook": {"cacheAuthorizedTTL": "0s", "cacheUnauthorizedTTL": "0s"},
        },
        "cgroupDriver": "systemd",
        "clusterDNS": [str(ipaddress.ip_network(service_subnet)[10])],
        "healthzBindAddress": "127.0.0.1",
        "healthzPort": 10248,
        "rotateCertificates": True,
        "staticPodPath": STATIC_POD_PATH,
    }
    if config.cluster_domain:
        kubelet_configuration["clusterDomain"] = config.cluster_domain

    return [
        config_map("kubelet-config", "kubelet", kubelet_configuration),
        *config_map_reader("kubeadm:kubelet-config", "kubelet-config"),
    ]


def generate_upload_config(
    config: PKIConfig,
    *,
    cluster_name: str,
    versions: Versions,
    control_plane_endpoint: str,
    service_subnet: str,
) -> bytes:
    """Generate the manifests of the upload-config phase."""
    objects = [
        *generate_upload_config_kubeadm(
            config,
            cluster_name=cluster_name,
            versions=versions,
            control_plane_endpoint=control_plane_endpoint,
            service_subnet=service_subnet,
        ),
        *generate_upload_config_kubelet(config, service_subnet=service_subnet),
    ]
    return to_yaml(objects)


# --- bootstrap-token ---------------------------------------------------------


def generate_bootstrap_token_phase(*, ca_cert_pem: bytes, server: str) -> bytes:
    """Generate the RBAC and the cluster-info ConfigMap needed to join nodes."""
    cluster_info = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [
            {
                "name": "",
                "cluster": {"certificate-authority-data": b64(ca_cert_pem), "server": server},
            }
        ],
        "contexts": [],
        "current-context": "",
        "preferences": {},
        "users": [],
    }
    bootstrappers = [rbac_group(BOOTSTRAP_TOKEN_GROUP)]
    objects = [
        {
            "apiVersion": f"{RBAC}/v1",
            "kind": "ClusterRole",
            "metadata": {"name": "kubeadm:get-nodes"},
            "rules": [{"apiGroups": [""], "resources": ["nodes"], "verbs": ["get"]}],
        },
        cluster_role_binding("kubeadm:get-nodes", "kubeadm:get-nodes", bootstrappers),
        cluster_role_binding(
            "kubeadm:kubelet-bootstrap", "system:node-bootstrapper", bootstrappers
        ),
        cluster_role_binding(
            "kubeadm:node-autoapprove-bootstrap",
            "system:certificates.k8s.io:certificatesigningrequests:nodeclient",
            bootstrappers,
        ),
        cluster_role_binding(
            "kubeadm:node-autoapprove-certificate-rotation",
            "system:certificates.k8s.io:certificatesigningrequests:selfnodeclient",
            [rbac_group(NODES_GROUP)],
        ),
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "cluster-info", "namespace": "kube-public"},
            "data": {"kubeconfig": yaml.safe_dump(cluster_info, sort_keys=False)},
        },
        get_one_role(
            "kubeadm:bootstrap-signer-clusterinfo", "kube-public", "configmaps", "cluster-info"
        ),
        role_binding(
            "kubeadm:bootstrap-signer-clusterinfo",
            "kube-public",
            [{"apiGroup": RBAC, "kind": "User", "name": "system:anonymous"}],
        ),
    ]
    return to_yaml(objects)


# --- addon -------------------------------------------------------------------


def generate_addon_coredns(config: PKIConfig, *, service_subnet: str, image: str) -> list[dict]:
    """Generate the CoreDNS manifests."""
    domain = config.cluster_domain or "cluster.local"
    labels = {"k8s-app": "kube-dns"}
    return [
        {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {"name": "coredns", "namespace": "kube-system"},
        },
        {
            "apiVersion": f"{RBAC}/v1",
            "kind": "ClusterRole",
            "metadata": {"name": "system:coredns"},
            "rules": [
                {
                    "apiGroups": [""],
                    "resources": ["endpoints", "services", "pods", "namespaces"],
                    "verbs": ["list", "watch"],
                },
                {"apiGroups": [""], "resources": ["nodes"], "verbs": ["get"]},
                {
                    "apiGroups": ["discovery.k8s.io"],
                    "resources": ["endpointslices"],
                    "verbs": ["list", "watch"],
                },
            ],
        },
        cluster_role_binding(
            "system:coredns",
            "system:coredns",
            [{"kind": "ServiceAccount", "name": "coredns", "namespace": "kube-system"}],
        ),
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "coredns", "namespace": "kube-system"},
            "data": {"Corefile": COREFILE.format(domain=domain)},
        },
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "coredns", "namespace": "kube-system", "labels": labels},
            "spec": {
                "replicas": 2,
                "strategy": {"type": "RollingUpdate", "rollingUpdate": {"maxUnavailable": 1}},
                "selector": {"matchLabels": labels},
                "template": {
                    "metadata": {"labels": labels},
                    "spec": {
                        "priorityClassName": "system-cluster-critical",
                        "serviceAccountName": "coredns",
                        "affinity": {
                            "podAntiAffinity": {
                                "preferredDuringSchedulingIgnoredDuringExecution": [
                                    {
                                        "weight": 100,
                                        "podAffinityTerm": {
                                            "labelSelector": {
                                                "matchExpressions": [
                                                    {
                                                        "key": "k8s-app",
                                                        "operator": "In",
                                                        "values": ["kube-dns"],
                                                    }
                                                ]
                                            },
                                            "topologyKey": "kubernetes.io/hostname",
                                        },
                                    }
                                ]
                            }
                        },
                        "tolerations": [
                            {"key": "CriticalAddonsOnly", "operator": "Exists"},
                            {
                                "key": "node-role.kubernetes.io/control-plane",
                                "effect": "NoSchedule",
                            },
                        ],
                        "nodeSelector": {"kubernetes.io/os": "linux"},
                        "containers": [
                            {
                                "name": "coredns",
                                "image": image,
                                "imagePullPolicy": "IfNotPresent",
                                "args": ["-conf", "/etc/coredns/Corefile"],
                                "resources": {
                                    "limits": {"memory": "170Mi"},
                                    "requests": {"cpu": "100m", "memory": "70Mi"},
                                },
                                "volumeMounts": [
                                    {
                                        "name": "config-volume",
                                        "mountPath": "/etc/coredns",
                                        "readOnly": True,
                                    }
                                ],
                                "ports": [
                                    {"name": "dns", "containerPort": 53, "protocol": "UDP"},
                                    {"name": "dns-tcp", "containerPort": 53, "protocol": "TCP"},
                                    {"name": "metrics", "containerPort": 9153, "protocol": "TCP"},
                                ],
                                "livenessProbe": {
                                    "httpGet": {"path": "/health", "port": 8080, "scheme": "HTTP"},
                                    "initialDelaySeconds": 60,
                                    "timeoutSeconds": 5,
                                    "successThreshold": 1,
                                    "failureThreshold": 5,
                                },
                                "readinessProbe": {
                                    "httpGet": {"path": "/ready", "port": 8181, "scheme": "HTTP"}
                                },
                                "securityContext": {
                                    "allowPrivilegeEscalation": False,
                                    "capabilities": {"add": ["NET_BIND_SERVICE"], "drop": ["ALL"]},
                                    "readOnlyRootFilesystem": True,
                                },
                            }
                        ],
                        "dnsPolicy": "Default",
                        "volumes": [
                            {
                                "name": "config-volume",
                                "configMap": {
                                    "name": "coredns",
                                    "items": [{"key": "Corefile", "path": "Corefile"}],
                                },
                            }
                        ],
                    },
                },
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": "kube-dns",
                "namespace": "kube-system",
                "labels": {
                    **labels,
                    "kubernetes.io/cluster-service": "true",
                    "kubernetes.io/name": "CoreDNS",
                },
                "annotations": {"prometheus.io/port": "9153", "prometheus.io/scrape": "true"},
            },
            "spec": {
                "selector": labels,
                "clusterIP": str(ipaddress.ip_network(service_subnet)[10]),
                "ports": [
                    {"name": "dns", "port": 53, "protocol": "UDP", "targetPort": 53},
                    {"name": "dns-tcp", "port": 53, "protocol": "TCP", "targetPort": 53},
                    {"name": "metrics", "port": 9153, "protocol": "TCP", "targetPort": 9153},
                ],
            },
        },
    ]


def generate_addon_kube_proxy(
    *, kubernetes_version: str, control_plane_endpoint: str
) -> list[dict]:
    """Generate the kube-proxy manifests."""
    sa_dir = "/var/run/secrets/kubernetes.io/serviceaccount"
    kubeconfig = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [
            {
                "name": "default",
                "cluster": {
                    "certificate-authority": f"{sa_dir}/ca.crt",
                    "server": f"https://{control_plane_endpoint}",
                },
            }
        ],
        "contexts": [
            {
                "name": "default",
                "context": {"cluster": "default", "namespace": "default", "user": "default"},
            }
        ],
        "current-context": "default",
        "users": [{"name": "default", "user": {"tokenFile": f"{sa_dir}/token"}}],
    }
    proxy_config = {
        "apiVersion": "kubeproxy.config.k8s.io/v1alpha1",
        "kind": "KubeProxyConfiguration",
        "bindAddress": "0.0.0.0",
        "clientConnection": {"kubeconfig": "/var/lib/kube-proxy/kubeconfig.conf"},
    }
    labels = {"k8s-app": "kube-proxy"}
    return [
        {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {"name": "kube-proxy", "namespace": "kube-system"},
        },
        cluster_role_binding(
            "kubeadm:node-proxier",
            "system:node-proxier",
            [{"kind": "ServiceAccount", "name": "kube-proxy", "namespace": "kube-system"}],
        ),
        get_one_role("kube-proxy", "kube-system", "configmaps", "kube-proxy"),
        role_binding("kube-proxy", "kube-system", [rbac_group(BOOTSTRAP_TOKEN_GROUP)]),
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "kube-proxy",
                "namespace": "kube-system",
                "labels": {"app": "kube-proxy"},
            },
            "data": {
                "config.conf": yaml.safe_dump(proxy_config, sort_keys=False),
                "kubeconfig.conf": yaml.safe_dump(kubeconfig, sort_keys=False),
            },
        },
        {
            "apiVersion": "apps/v1",
            "kind": "DaemonSet",
            "metadata": {"name": "kube-proxy", "namespace": "kube-system", "labels": labels},
            "spec": {
                "selector": {"matchLabels": labels},
                "updateStrategy": {"type": "RollingUpdate"},
                "template": {
                    "metadata": {"labels": labels},
                    "spec": {
                        "priorityClassName": "system-node-critical",
                        "hostNetwork": True,
                        "serviceAccountName": "kube-proxy",
                        "nodeSelector": {"kubernetes.io/os": "linux"},
                        "tolerations": [{"operator": "Exists"}],
                        "containers": [
                            {
                                "name": "kube-proxy",
                                "image": f"{IMAGE_REPOSITORY}/kube-proxy:{kubernetes_version}",
                                "imagePullPolicy": "IfNotPresent",
                                "command": [
                                    "/usr/local/bin/kube-proxy",
                                    "--config=/var/lib/kube-proxy/config.conf",
                                    "--hostname-override=$(NODE_NAME)",
                                ],
                                "env": [
                                    {
                                        "name": "NODE_NAME",
                                        "valueFrom": {"fieldRef": {"fieldPath": "spec.nodeName"}},
                                    }
                                ],
                                "securityContext": {"privileged": True},
                                "volumeMounts": [
                                    {"name": "kube-proxy", "mountPath": "/var/lib/kube-proxy"},
                                    {"name": "xtables-lock", "mountPath": "/run/xtables.lock"},
                                    {
                                        "name": "lib-modules",
                                        "mountPath": "/lib/modules",
                                        "readOnly": True,
                                    },
                                ],
                            }
                        ],
                        "volumes": [
                            {"name": "kube-proxy", "configMap": {"name": "kube-proxy"}},
                            {
                                "name": "xtables-lock",
                                "hostPath": {"path": "/run/xtables.lock", "type": "FileOrCreate"},
                            },
                            {"name": "lib-modules", "hostPath": {"path": "/lib/modules"}},
                        ],
                    },
                },
            },
        },
    ]


def generate_addons(
    config: PKIConfig,
    *,
    versions: Versions,
    control_plane_endpoint: str,
    service_subnet: str,
) -> bytes:
    """Generate the manifests of the addon phase."""
    return to_yaml(
        [
            *generate_addon_coredns(
                config, service_subnet=service_subnet, image=versions.coredns_image
            ),
            *generate_addon_kube_proxy(
                kubernetes_version=versions.kubernetes,
                control_plane_endpoint=control_plane_endpoint,
            ),
        ]
    )


# --- konnectivity ------------------------------------------------------------


def generate_egress_selector_config(*, server_url: str, pki_dir: str = PKI_DIR) -> bytes:
    """Generate the API server egress selector configuration."""
    config = {
        "apiVersion": "apiserver.k8s.io/v1beta1",
        "kind": "EgressSelectorConfiguration",
        "egressSelections": [
            {
                "name": "cluster",
                "connection": {
                    "proxyProtocol": "HTTPConnect",
                    "transport": {
                        "tcp": {
                            "url": server_url,
                            "tlsConfig": {
                                "caBundle": f"{pki_dir}/konnectivity/ca.crt",
                                "clientCert": f"{pki_dir}/konnectivity/client.crt",
                                "clientKey": f"{pki_dir}/konnectivity/client.key",
                            },
                        }
                    },
                },
            }
        ],
    }
    return yaml.safe_dump(config, sort_keys=False).encode("utf-8")


def generate_konnectivity_agent(*, image: str, server_host: str, server_port: int = 8132) -> bytes:
    """Generate the konnectivity-agent manifests."""
    sa = KONNECTIVITY_AGENT_SA
    token_dir = "/var/run/secrets/tokens"
    labels = {"k8s-app": KONNECTIVITY_AGENT_SA}
    return to_yaml(
        [
            cluster_role_binding(
                KONNECTIVITY_USER,
                "system:auth-delegator",
                [{"apiGroup": RBAC, "kind": "User", "name": KONNECTIVITY_USER}],
            ),
            {
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": {"name": sa, "namespace": "kube-system"},
            },
            {
                "apiVersion": "apps/v1",
                "kind": "DaemonSet",
                "metadata": {"name": sa, "namespace": "kube-system", "labels": labels},
                "spec": {
                    "selector": {"matchLabels": labels},
                    "template": {
                        "metadata": {"labels": labels},
                        "spec": {
                            "priorityClassName": "system-cluster-critical",
                            "serviceAccountName": sa,
                            "nodeSelector": {"kubernetes.io/os": "linux"},
                            "tolerations": [{"key": "CriticalAddonsOnly", "operator": "Exists"}],
                            "containers": [
                                {
                                    "name": sa,
                                    "image": image,
                                    "args": [
                                        "--logtostderr=true",
                                        f"--ca-cert={SA_CA_CERT}",
                                        f"--proxy-server-host={server_host}",
                                        f"--proxy-server-port={server_port}",
                                        f"--admin-server-port={KONNECTIVITY_ADMIN_PORT}",
                                        f"--health-server-port={KONNECTIVITY_HEALTH_PORT}",
                                        f"--service-account-token-path={token_dir}/{sa}-token",
                                    ],
                                    "volumeMounts": [
                                        {"name": f"{sa}-token", "mountPath": token_dir}
                                    ],
                                    "livenessProbe": {
                                        "httpGet": {
                                            "port": KONNECTIVITY_HEALTH_PORT,
                                            "path": "/healthz",
                                        },
                                        "initialDelaySeconds": 15,
                                        "timeoutSeconds": 15,
                                    },
                                }
                            ],
                            "volumes": [
                                {
                                    "name": f"{sa}-token",
                                    "projected": {
                                        "sources": [
                                            {
                                                "serviceAccountToken": {
                                                    "path": f"{sa}-token",
                                                    "audience": KONNECTIVITY_AUDIENCE,
                                                }
                                            }
                                        ]
                                    },
                                }
                            ],
                        },
                    },
                },
            },
        ]
    )


# --- kubernetes Service endpoint --------------------------------------------


def generate_kubernetes_endpoints(*, ip: str, port: int) -> bytes:
    """Generate the endpoints of the kubernetes Service."""
    port_spec = {"name": "https", "port": port, "protocol": "TCP"}
    return to_yaml(
        [
            {
                "apiVersion": "v1",
                "kind": "Endpoints",
                "metadata": {
                    "name": "kubernetes",
                    "namespace": "default",
                    # The EndpointSlice below is explicit: do not mirror.
                    "labels": {"endpointslice.kubernetes.io/skip-mirror": "true"},
                },
                "subsets": [{"addresses": [{"ip": ip}], "ports": [port_spec]}],
            },
            {
                "apiVersion": "discovery.k8s.io/v1",
                "kind": "EndpointSlice",
                "metadata": {
                    "name": "kubernetes",
                    "namespace": "default",
                    "labels": {"kubernetes.io/service-name": "kubernetes"},
                },
                "addressType": "IPv4",
                "endpoints": [{"addresses": [ip], "conditions": {"ready": True}}],
                "ports": [port_spec],
            },
        ]
    )


# --- cluster admins RBAC -----------------------------------------------------


def generate_cluster_admins_rbac() -> bytes:
    """Generate the ClusterRoleBinding of the cluster admins."""
    return to_yaml(
        [
            cluster_role_binding(
                CLUSTER_ADMINS_GROUP, "cluster-admin", [rbac_group(CLUSTER_ADMINS_GROUP)]
            )
        ]
    )
