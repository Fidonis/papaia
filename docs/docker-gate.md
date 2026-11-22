# The Docker socket broker: papaia-docker-gate

Whoever can talk to the Docker socket is root on the host: one `create` with the host's `/`
mounted, or one `exec` into a container that holds keys, is enough. `papaia-docker-gate` is the
manager's narrow way to Docker. It holds the socket; the manager talks HTTP to it over an
internal network, and the gate decides every request before anything reaches the socket.

```
papaia-manager --> papaia-docker-gate-net --> papaia-docker-gate --> /var/run/docker.sock
                   (internal: true,           allow list,           (mounted read-only)
                    manager and gate only)    audit row per write
```

The gate runs with the manager (profile `manager`). It publishes no port.

## What it allows

The gate speaks a small part of the Docker Engine API, at `http://papaia-docker-gate:2375`,
with or without a version prefix such as `/v1.47`:

| Request | What the gate does |
|---|---|
| `GET` / `HEAD /_ping`, `GET /version` | passed through, for client version negotiation |
| `GET /containers/json` (`all`, `filters`) | the containers of the named projects only, each cut to `Id`, `Names`, `Image`, `ImageID`, `Created`, `State`, `Status`, `Labels` |
| `GET /containers/{id}/json` | a container of a named project, cut to its id, name, image, state (health status without probe output) and labels |
| `POST /containers/{id}/start` | a container of a named project |
| `POST /containers/{id}/stop` (`t` up to 600 seconds) | a container of a named project |

The **named projects** are the compose projects in `DOCKER_GATE_PROJECTS`; the compose file sets
it to the installation's own project, `COMPOSE_PROJECT_NAME`. A container belongs to a project
through its label `com.docker.compose.project`. For `start` and `stop` the gate looks the
container up and then acts on the full id it found, so a name cannot be moved to another
container between the check and the call.

No environment, command line, mount, host configuration or health-check output leaves the gate:
those may hold secrets of the services.

## What it refuses

Everything else is refused with `403` and `{"error": "docker_gate.not_allowed"}` before the socket
is touched, among others:

- `exec` (`POST /containers/{id}/exec`, `/exec/...`);
- `create` (`POST /containers/create`), with or without host mounts, and every other way to
  create something: volumes, networks, images, builds, services;
- `kill`, `restart`, `update`, `rename`, `attach`, `logs`, archives, `export`, `DELETE`;
- `info`, `events` and every other read of the host;
- API versions below 1.24 and paths with `//` or `/.`.

A container of another project, a container without a compose project and an unknown container
are refused alike with `403` and `docker_gate.foreign_project`; the answer does not tell which
containers exist elsewhere on the host.

An allowed call with input that does not fit is rejected with `400` and
`docker_gate.invalid_request`: an unknown or repeated query parameter, `filters` that are not a
JSON object of string lists, `t` outside 0..600, a container reference that is not a Docker name
or id, any request body, `Transfer-Encoding`.

## Audit

Every `start` and `stop` and every refusal is one `papaia.audit/1` line on the gate's standard
output (the submission form; the delivering writer numbers the rows):

- `writer` and `catalog_id`: `papaia-docker-gate`; `role`: `server`; `event`: `operation`;
- `operation`: `docker_gate.container_start`, `docker_gate.container_stop`,
  `docker_gate.container_exec`, `docker_gate.container_create`,
  `docker_gate.container_inspect` or `docker_gate.request`;
- `effect`: `write` or `read`; `result`: `allowed`, `denied` or `error`; `error_code` as above,
  `docker_gate.upstream_failed` when Docker does not answer;
- `object_ref`: `{"type": "container", "id": ...}` where the request named one;
- `correlation_id`: the `X-Papaia-Correlation-Id` of the request, or a new UUIDv7 when it is
  missing or not usable; the gate returns it in the same header;
- the caller: `papaia-manager` as `sub`, `service_account` and `azp`. There is no token; the
  caller is known by its network, which holds the manager and the gate only.

Reading status is not audited. No body, query value or container content is ever written.

## Limits of the gate

- **Not supported without the gate.** The manager compose file of this release still mounts the
  socket; the manager moves to the gate in its own release. Until then the manager keeps
  root-equivalent access to the host. With the gate as its only way, the manager can read the
  status of the installation's containers and start and stop them, nothing else.
- **The read-only mount is not the control.** A read-only bind mount of a Unix socket does not
  stop requests through it; the allow list in the gate does.
- **Inside the named project.** `stop` of any container of the installation's project is
  allowed, the gate and the audit store included. That is an outage, not a way to data: the
  operator starts them again with `papaia-ctl start`.
- Anyone with root on the host, or with the socket outside the gate, is not bound by it.

## Operation

- Turned on and off with the `manager` profile; nothing to configure.
- The gate runs as an unprivileged user with the group that owns the socket on the host:
  `DOCKER_GID` in `src/.env` (the same value the manager uses).
- Health check: the listener on port 2375; no request is made, so the check writes no audit line.
- No add-on may attach `papaia-docker-gate` (`networks.attach` is refused by `papaia-ctl`).
