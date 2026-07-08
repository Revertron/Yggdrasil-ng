# Container Image

Release container images are published to GitHub Container Registry:

```text
ghcr.io/revertron/yggdrasil-ng
```

When a release tag is pushed, for example `v0.2.1`, the CI publishes:

- `ghcr.io/revertron/yggdrasil-ng:0.2.1`
- `ghcr.io/revertron/yggdrasil-ng:latest`

Use version tags for pinned deployments. The `latest` tag follows the newest release tag.
Images are built for `linux/amd64` and `linux/arm64`.

## Run with Docker or Podman

The container starts `yggdrasil` with `/data/config.toml`. If that file does not exist, the entrypoint generates it on first start.

```bash
mkdir -p ./yggdrasil-data

docker run -d \
  --name yggdrasil-ng \
  --restart unless-stopped \
  --cap-add NET_ADMIN \
  --device /dev/net/tun \
  -v "$PWD/yggdrasil-data:/data" \
  ghcr.io/revertron/yggdrasil-ng:latest
```

Use the same arguments with `podman run` if you prefer Podman.

After the first start, edit `./yggdrasil-data/config.toml` to add peers or change listeners, then restart the container:

```bash
docker restart yggdrasil-ng
```

For a pinned release, replace `latest` with the release version:

```bash
ghcr.io/revertron/yggdrasil-ng:0.2.1
```

## Networking Modes

The container always needs `NET_ADMIN` and access to `/dev/net/tun` so it can create a TUN interface.

The base command above does not use host networking, so Yggdrasil runs inside the container network namespace. Use this mode when Yggdrasil connectivity should be available to other containers through a shared Docker/Podman network, a Podman pod, or a similar container networking setup.

If the Yggdrasil interface and routes should be available on the host itself, add host networking to the base command:

```text
--network host
```

If you do not use host networking but want to accept incoming peers from outside Docker/Podman, publish the listener port and configure a matching `listen` entry in `/data/config.toml`:

```text
-p 12345:12345/tcp
```

With Podman, the non-host-network mode can be used rootless when your environment allows passing `/dev/net/tun`. Host networking usually requires rootful Podman.
