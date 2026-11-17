import io
import tarfile
import time
from dataclasses import dataclass, field

import docker
from docker.errors import ImageNotFound, NotFound


@dataclass
class Container:
    """Class that manages Docker containers."""

    name: str
    image: str | None = None
    command: str | list[str] | None = None
    env: dict[str, str] | None = None
    volumes: dict[str, dict[str, str]] | None = None
    network: str | None = None
    ports: dict[str, int | tuple[str, int] | list[tuple[str, int]]] | None = None
    hostname: str | None = None
    user: str | None = None  # e.g. "0" to override the image user
    labels: dict[str, str] | None = None
    restart_policy: str | None = None  # e.g. "unless-stopped"
    # Pass a shared client (e.g. Cluster.client); a new one is opened otherwise.
    client: docker.DockerClient = field(
        default_factory=docker.from_env, kw_only=True, repr=False, compare=False
    )

    def create(self) -> str:
        """Create the container."""
        if not self.image:
            raise ValueError(f"container {self.name!r}: image is required to create it")
        try:
            self.client.images.get(self.image)
        except ImageNotFound:
            self.client.images.pull(self.image)
        container = self.client.containers.create(
            self.image,
            self.command,
            name=self.name,
            environment=self.env,
            volumes=self.volumes,
            network=self.network,
            ports=self.ports,
            hostname=self.hostname,
            user=self.user,
            labels=self.labels,
            restart_policy={"Name": self.restart_policy} if self.restart_policy else None,
        )
        return container.id

    def put_files(self, files: dict[str, tuple[bytes, int]], dest: str = "/") -> None:
        """Copy files into the container."""
        buffer = io.BytesIO()
        now = time.time()
        with tarfile.open(fileobj=buffer, mode="w") as tar:
            for path, (content, mode) in files.items():
                info = tarfile.TarInfo(path)
                info.size = len(content)
                info.mode = mode
                info.mtime = now
                tar.addfile(info, io.BytesIO(content))
        self.client.containers.get(self.name).put_archive(dest, buffer.getvalue())

    def get_files(self, path: str) -> dict[str, bytes]:
        """Read files from the container."""
        stream, _ = self.client.containers.get(self.name).get_archive(path)
        buffer = io.BytesIO(b"".join(stream))
        files = {}
        with tarfile.open(fileobj=buffer) as tar:
            for member in tar.getmembers():
                if member.isfile():
                    relative = member.name.split("/", 1)[1]
                    files[relative] = tar.extractfile(member).read()
        return files

    def exists(self) -> bool:
        """Check whether the container exists."""
        try:
            self.client.containers.get(self.name)
        except NotFound:
            return False
        return True

    def status(self) -> str:
        """Return the container state."""
        return self.client.containers.get(self.name).status

    def is_running(self) -> bool:
        """Check whether the container is running."""
        return self.status() == "running"

    def wait(self) -> int:
        """Wait for the container to exit and return its exit code."""
        return self.client.containers.get(self.name).wait()["StatusCode"]

    def logs(self, *, stderr: bool = True) -> str:
        """Return the container logs."""
        raw = self.client.containers.get(self.name).logs(stdout=True, stderr=stderr)
        return raw.decode("utf-8", "replace")

    def start(self) -> None:
        """Start the container."""
        self.client.containers.get(self.name).start()

    def unpause(self) -> None:
        """Unpause the container."""
        self.client.containers.get(self.name).unpause()

    def stop(self, timeout: int = 10) -> None:
        """Stop the container."""
        self.client.containers.get(self.name).stop(timeout=timeout)

    def restart(self, timeout: int = 10) -> None:
        """Restart the container."""
        self.stop(timeout)
        self.start()

    def delete(self, *, force: bool = False) -> None:
        """Delete the container."""
        self.client.containers.get(self.name).remove(force=force)
