# kuberd

[![pylint](https://github.com/vcoscia1/kuberd/actions/workflows/pylint.yml/badge.svg)](https://github.com/vcoscia1/kuberd/actions/workflows/pylint.yml)
![Python](https://img.shields.io/badge/python-3.12%2B-3776AB?logo=python&logoColor=white)
![Kubernetes](https://img.shields.io/badge/kubernetes-1.35%2B-326CE5?logo=kubernetes&logoColor=white)
![Docker](https://img.shields.io/badge/docker-required-2496ED?logo=docker&logoColor=white)

kuberd runs several Kubernetes control planes in Docker, so you can join external VMs to them as worker nodes with `kubeadm join`.

Each control plane is a single instance (no HA) made of these containers:

- etcd
- kube-apiserver
- kube-controller-manager
- kube-scheduler
- konnectivity-server
- toolbox with kubectl and kubeadm

## 📋 Requirements

- Python 3.12+
- Docker (tested with Docker Desktop on macOS)
- Access to `registry.k8s.io` and `dl.k8s.io`

## 📦 Installation

```sh
python3 -m venv .venv
.venv/bin/pip install -e .
```

The `kuberd` command is then available as `.venv/bin/kuberd`. For development, `.venv/bin/pip install -e ".[dev]"` also installs pylint.

## ⚙️ Configuration

Each cluster is described by its own YAML file (see [cluster.example.yaml](cluster.example.yaml)):

| Key | Description | Default | Required |
|---|---|---|---|
| `apiVersion` | `kuberd/v1alpha1` | - | yes |
| `kind` | `Cluster` | - | yes |
| `name` | Cluster name, used for containers, volumes and network (max 40 chars) | - | yes |
| `nodeEndpointIP` | IPv4 address of this host reachable from the VMs | - | yes |
| `apiPort` | Host port of the API server, on `nodeEndpointIP` and `127.0.0.1` | `30000` | no |
| `konnectivityPort` | Host port for the konnectivity agents, on `nodeEndpointIP` | `30001` | no |
| `serviceCIDR` | Service network (IPv4) | `10.96.0.0/12` | no |
| `clusterDomain` | Cluster DNS domain | `cluster.local` | no |
| `extraAPIServerSANs` | Extra API server certificate SANs (IPv4 or DNS names) | `[]` | no |
| `kubernetesVersion` | Kubernetes version, `vMAJOR.MINOR.PATCH`, 1.35 or later 1.x | `v1.35.0` | no |
| `etcdVersion` | etcd image tag | `3.6.6-0` | no |
| `corednsVersion` | CoreDNS image tag | `v1.13.1` | no |
| `konnectivityVersion` | konnectivity server and agent image tag | `v0.34.0` | no |

The versions can also be set with `kuberd create` flags (`--kubernetes-version`, `--etcd-version`, `--coredns-version`, `--konnectivity-version`), which override the file. Before creating anything, kuberd checks that every image exists locally or on `registry.k8s.io`.

Clusters on the same host need different `name`, `apiPort` and `konnectivityPort`. Internal ports stay standard (6443, 8132). If a host port is busy, `create` stops and suggests a free one.

## 🚀 Usage

```sh
kuberd create -f cluster.yaml      # create a cluster (does nothing if it already exists)
kuberd list                        # list all clusters and their container states
kuberd kubeconfig <name>           # save the admin kubeconfig to ./<name>.kubeconfig (0600)
kuberd stop <name>                 # stop the containers of cluster <name>
kuberd start <name>                # start the containers of cluster <name>
kuberd delete <name>               # remove the containers, volumes and network of cluster <name>
```

Join a VM as a worker node:

```sh
docker exec <name>-toolbox kubeadm token create --print-join-command
```

The printed command uses the internal endpoint: on the VM, run it with `<nodeEndpointIP>:<apiPort>` instead of `<name>-kube-apiserver:6443`.
kuberd installs no CNI, so nodes stay `NotReady` until one is installed.

Check cluster status:

```sh
kubectl --kubeconfig <name>.kubeconfig get pods -A
docker exec <name>-toolbox kubectl get nodes
```

## 📁 Repository Structure

- `kuberd/cli.py`: command line interface
- `kuberd/cluster.py`: `Cluster` class, Docker lifecycle of a cluster
- `kuberd/kubeadm.py`: kubeadm-style PKI, kubeconfigs and phase manifests (upload-config, bootstrap-token, addons, konnectivity)
- `kuberd/pki.py`: X.509 primitives (ECDSA P-256 CAs and certificates, RSA ServiceAccount key)
- `kuberd/config.py`: configuration file loading and validation
- `kuberd/container.py`: `Container` wrapper around the Docker SDK
- `kuberd/versions.py`: component versions and their images
- `kuberd/constants.py`, `kuberd/utils.py`: shared constants and helpers
- `cluster.example.yaml`: example configuration
