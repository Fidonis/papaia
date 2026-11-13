---
adr: 0012
title: Serve local inference on Apple Silicon through a native LocalAI
status: Proposed
date: 2026-11-13
deciders:
  - marko-boehm
  - fwahl711
tags:
  - localai
  - macos
  - inference
supersedes: null
superseded_by: null
---

# 0012. Serve local inference on Apple Silicon through a native LocalAI

## Context

On macOS the stack runs in Docker Desktop's Linux VM, which has no access to the Apple GPU.
LocalAI in a container therefore always runs on the CPU, and in the VM's memory next to the
rest of the stack. Apple Silicon Macs are used for development and evaluation, where a local
model has to answer at a usable speed without a server.

LocalAI publishes a signed and notarised macOS binary with every release
(`local-ai-v<version>-darwin-arm64`, next to `LocalAI-v<version>-checksums.txt`). Its backend
catalogue maps `llama-cpp` to Metal on darwin/arm64. Run as a host process, it uses the
Apple GPU with the same engine, the same model list and the same LiteLLM registration
(Fidonis/papaia#365) as the container on Linux.

Measured on an M4 Max (128 GB, macOS 27.2) with Docker Desktop 29.8.2 and Compose 5.6.0, the
Docker VM at 8 GB, LocalAI v4.7.1 (Fidonis/papaia#366):

| | native (Metal) | CPU container in the VM |
|---|---|---|
| Chat, Qwen2.5-7B-Instruct Q5_K_M | 57.6 tokens/s | killed by the VM's OOM killer while loading the model next to the stack |
| Embeddings, nomic-embed-text v1.5 Q8_0 | about 0.44 s per paragraph (same on CPU and Metal) | about ten times faster |

Also checked on that Mac:

- the binary's sha256 matches the release's checksum line and it is signed by the publisher;
- `deploy.replicas: 0` alone still pulls the image; with `pull_policy: never` nothing is
  pulled and the other services start;
- files the init job writes as root into a bind mount below `/Users` belong to the operator
  on the host, who can read and delete them; the job needs no other user;
- the darwin binary does **not start with `LOCALAI_AUTH=true`** ("SQLite auth database
  requires building with -tags auth (CGO)"). Without it, `LOCALAI_API_KEY` still protects
  `/v1`, `/api` and `/metrics`, and `/readyz` needs no key;
- LocalAI writes `data/` and `configuration/` into its working directory.

## Decision

On an Apple Silicon Mac with Docker Desktop, LocalAI can run as a host process instead of a
container. A sticky root setting `LOCALAI_RUNTIME` (`container`, the default, or `native`),
set by `papaia-ctl setup --localai-runtime=…`, selects it; setup asks on such a Mac only and
refuses the flag elsewhere. A distributed installation refuses `native`.

- **Compose.** The services `localai` and `localai-model-init` stay declared (the add-on
  contract pins them). A generated override sets `pull_policy: never` and `replicas: 0` on
  `localai`, and mounts `<home>/models` into the init job instead of the `localai-models`
  volume. It is removed again for `container`.
- **Home.** Everything lives in `<PAPAIA_WORKSPACE_DIR>/localai/<COMPOSE_PROJECT_NAME>`,
  derived and not a setting: outside `$PAPAIA_CONFIG_DIR`, which the backup archives in full,
  below `/Users`, which Docker Desktop shares, and at the same path inside papaia-manager.
- **Binary.** `start` installs the release of the pinned `localai` image (one pin for both
  runtimes): download, sha256 against the published checksums, atomic rename, older binaries
  removed. It writes `<home>/run-localai`, which reads the key from the LocalAI `.env` when it
  runs, changes into `<home>` and starts LocalAI on `127.0.0.1:<LOCALAI_EXT_PORT>` without
  `LOCALAI_AUTH`.
- **Process.** launchd runs that script as a LaunchAgent of the logged-in user
  (`de.fidonis.papaia.<COMPOSE_PROJECT_NAME>.localai`, Fidonis/papaia#367): `start` enables
  and loads the job after `docker compose up` and waits up to 60 s for `/readyz`, restarting
  it for a new binary or start script; `stop` unloads and disables it, so it stays off after
  a login; `uninstall` removes it. The plist names only the script, so the key is in no plist.
  Inside a container (papaia-manager) these steps warn and are skipped.
- **LiteLLM** reaches the process at `http://host.docker.internal:<LOCALAI_EXT_PORT>/v1`, which
  Docker Desktop resolves in every container.
- **Models.** When the runtime changes to `native`, setup seeds the overlay `models.txt` once
  with an active chat model and `nomic-embed-text`. The chat model is Qwen2.5-7B-Instruct
  Q5_K_M: 58 tokens/s on Metal is fast enough for a chat, and its 5.4 GB fit a 16 GB Mac
  next to the stack. The 1.5B model stays in the list for smaller machines.
- **status and doctor** do not expect a `localai` container for `native`. A new doctor check,
  `localai_native`, probes `/readyz`, compares the installed binary with the pin and, on the
  Mac, reads the launchd job's state; it is `warn` at most.

## Consequences

- **Positive**: chat with a local model on the Apple GPU at about 58 tokens/s on a Mac, with
  the engine, model list and registration that Linux uses; no second engine.
- **Positive**: the CPU container, which does not even load a 7B model in the default VM,
  stops being the only choice on a Mac.
- **Negative**: one process outside Compose, managed through launchd. It belongs to the user
  logged in on the Mac: papaia-manager, which runs in a container, cannot start or stop it,
  and LocalAI runs only while that user is logged in. Stopping the stack other than with
  `papaia-ctl stop` leaves the job enabled, and launchd starts it again at the next login.
- **Negative**: macOS may deny a launchd job access to `~/Documents`, `~/Desktop` and
  `~/Downloads`; `setup` warns when the LocalAI directory lies below one of them.
- **Negative**: no login for LocalAI's web UI. The darwin build has no auth database, so the
  OIDC client is not used; the API key is the only protection, and the process listens on
  `127.0.0.1` only, so the web UI is reachable on the Mac alone.
- **Negative**: the key has admin rights in LocalAI (it can install and delete models). It
  lives only in the two `.env` files and is read by the start script when it runs.
- **Negative**: models are not part of the backup; `start` downloads them again after a
  restore. The Metal backend comes from LocalAI's catalogue with a `latest` tag on the first
  start, so the first start needs internet access and is not tied to the pinned release.
- **Negative**: embeddings are about ten times slower natively than in the container on the
  same Mac, on CPU and Metal alike. Re-measure with a newer LocalAI (Fidonis/papaia#363)
  before relying on native embeddings for large uploads.
- **Neutral**: no new value in the LocalAI variant catalogue, which papaia-manager mirrors;
  a runtime is not an image variant. papaia-manager shows the native runtime in
  Fidonis/papaia-manager#204.
- **Neutral**: existing Macs stay on `container`; models in the old volume are not moved.

## Alternatives considered

- **Docker Model Runner** (Fidonis/papaia#311, Fidonis/papaia#314) — a second engine with its
  own model management, tied to Docker Desktop, an API without authentication, and models
  outside the Docker volumes and the backup.
- **Ollama on the host** — also a second engine with its own model management.
- **A `metal` LocalAI image variant** — no such image exists, and papaia-manager mirrors the
  variant catalogue in its contract test.
- **LocalAI's DMG launcher** — cannot be scripted, and its version is not pinned.
- **A LaunchDaemon** (system domain) — runs without a logged-in user, but needs root and
  another file layout; a Mac that runs papAIa has a user logged in anyway.
- **Homebrew services** — a dependency the stack does not otherwise have, and the version
  would not follow the pin.

## References

- Fidonis/papaia#366 (this decision), #365 (key and generated registration), #367 (launchd).
- Fidonis/papaia-manager#204 (the runtime in papaia-manager).
- [LocalAI releases](https://github.com/mudler/LocalAI/releases).
