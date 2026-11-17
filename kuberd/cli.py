"""kuberd command line interface.

    kuberd create -f cluster.yaml     create a cluster (does nothing if it exists)
    kuberd delete NAME                remove containers, volumes and network
    kuberd start NAME                 start the containers of a cluster
    kuberd stop NAME                  stop the containers of a cluster
    kuberd kubeconfig NAME [-o FILE]  save the admin kubeconfig (0600)
    kuberd list                       list clusters and container states
"""

import argparse
import logging
import os
import sys
from pathlib import Path

import docker
from docker.errors import DockerException

from kuberd.cluster import Cluster, list_clusters
from kuberd.config import ConfigError, load_config

log = logging.getLogger("kuberd")


class CLIError(Exception):
    """Error reported to the user without a traceback."""


def _existing(cluster: Cluster) -> Cluster:
    """Return the cluster if it exists, otherwise raise an error."""
    if not cluster.exists():
        raise CLIError(f"cluster {cluster.name!r} not found")
    return cluster


def create(cluster: Cluster) -> None:
    """Create a cluster and log its endpoints."""
    if not cluster.create():
        log.info("cluster %r already exists: nothing to do", cluster.name)
        return
    log.info("cluster %r ready", cluster.name)
    log.info("API (local): %s", cluster.local_server)
    log.info("API (nodes): %s", cluster.node_server)
    log.info("kubeconfig: kuberd kubeconfig %s", cluster.name)
    log.info("toolbox: docker exec -it %s bash", cluster.container_name("toolbox"))


def save_kubeconfig(cluster: Cluster, path: Path, *, force: bool = False) -> None:
    """Write the admin kubeconfig of a cluster to a file readable only by its owner."""
    files = _existing(cluster).read_pki()
    if not files or "admin.conf" not in files:
        raise CLIError(f"cluster {cluster.name!r} has no admin kubeconfig")
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if force else os.O_EXCL)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        raise CLIError(f"{path} already exists: use --force to overwrite it") from None
    os.fchmod(fd, 0o600)  # also tighten an existing file
    with os.fdopen(fd, "wb") as f:
        f.write(files["admin.conf"])
    log.info("admin kubeconfig saved to %s", path)
    log.info("kubectl --kubeconfig %s get pods -A", path)


def print_clusters(client: docker.DockerClient) -> None:
    """Print the clusters and the state of their containers."""
    clusters = list_clusters(client)
    if not clusters:
        print("no clusters")
        return
    for name in sorted(clusters):
        containers = clusters[name]
        running = sum(status == "running" for status in containers.values())
        print(f"{name}\t{running}/{len(containers)} containers running")
        for container, status in sorted(containers.items()):
            print(f"  {container}\t{status}")


def build_parser() -> argparse.ArgumentParser:
    """Build the command line parser."""
    parser = argparse.ArgumentParser(
        prog="kuberd", description="Kubernetes control planes on Docker"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("create", help="create a cluster from a configuration file")
    p.add_argument("-f", "--file", required=True, help="cluster configuration (YAML)")
    # Override the versions of the configuration file.
    p.add_argument("--kubernetes-version", help="e.g. v1.35.0 (1.35 or later 1.x)")
    p.add_argument("--etcd-version", help="e.g. 3.6.6-0")
    p.add_argument("--coredns-version", help="e.g. v1.13.1")
    p.add_argument("--konnectivity-version", help="e.g. v0.34.0")

    for command, text in (
        ("delete", "remove containers, volumes and network of a cluster"),
        ("start", "start the containers of a cluster"),
        ("stop", "stop the containers of a cluster"),
    ):
        sub.add_parser(command, help=text).add_argument("name", help="cluster name")

    p = sub.add_parser("kubeconfig", help="save the admin kubeconfig of a cluster")
    p.add_argument("name", help="cluster name")
    p.add_argument("-o", "--output", help="output file (default: ./NAME.kubeconfig)")
    p.add_argument("--force", action="store_true", help="overwrite an existing file")

    sub.add_parser("list", help="list clusters")
    return parser


def run(args: argparse.Namespace, client: docker.DockerClient) -> None:
    """Run the selected command."""
    if args.command == "list":
        print_clusters(client)
        return
    if args.command == "create":
        config = load_config(
            args.file,
            overrides={
                "kubernetesVersion": args.kubernetes_version,
                "etcdVersion": args.etcd_version,
                "corednsVersion": args.coredns_version,
                "konnectivityVersion": args.konnectivity_version,
            },
        )
        create(Cluster(config.name, config, client=client))
        return

    cluster = _existing(Cluster(args.name, client=client))
    if args.command == "delete":
        for resource in cluster.delete():
            log.warning(
                "%s left in place: it does not belong to cluster %r", resource, cluster.name
            )
        log.info("cluster %r deleted", cluster.name)
    elif args.command == "start":
        cluster.start()
        log.info("cluster %r started", cluster.name)
    elif args.command == "stop":
        cluster.stop()
        log.info("cluster %r stopped", cluster.name)
    elif args.command == "kubeconfig":
        path = Path(args.output or f"{cluster.name}.kubeconfig")
        save_kubeconfig(cluster, path, force=args.force)


def main(argv: list[str] | None = None) -> int:
    """Parse the arguments, run the command and return the exit code."""
    args = build_parser().parse_args(argv)
    # -v turns on debug output for kuberd only, not for docker/urllib3.
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    log.setLevel(logging.DEBUG if args.verbose else logging.INFO)
    try:
        client = docker.from_env()
    except DockerException as e:
        log.error("cannot connect to Docker: %s", e)
        return 1
    try:
        run(args, client)
    except (CLIError, ConfigError, RuntimeError, DockerException, OSError) as e:
        log.error("%s", e)
        return 1
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
