---
adr: 0011
title: Serve local inference on Apple Silicon through Docker Model Runner on the host, next to LocalAI
status: Proposed
date: 2026-11-04
deciders:
  - fwahl711
tags:
  - inference
  - macos
  - litellm
  - setup
supersedes: null
superseded_by: null
---

# 0011. Serve local inference on Apple Silicon through Docker Model Runner on the host, next to LocalAI

## Context

LocalAI is the only local inference engine of the core. It runs as a container, and
`papaia-ctl setup` picks its image variant from what `tools/lib/gpu_detect.py` finds on
the host (`/sys/class/drm`, `nvidia-smi`). On macOS the container runs in Docker
Desktop's Linux VM, which does not pass the Apple GPU through. The detection finds
neither, falls back to `cpu`, and a Mac always serves its models from the CPU.

Running on the GPU does not work from inside the container, on any route:

- There is no Metal or MLX inside a Linux container on macOS. A `metal` LocalAI image
  does not exist.
- Vulkan inside the VM (libkrun) is not available under Docker Desktop and would have no
  MLX backend anyway.
- LocalAI's native macOS build (the DMG launcher) runs on the GPU, but Compose cannot
  start it and `papaia-ctl` cannot start or stop it. It would also bring a second OIDC
  client to keep in sync.

Docker Desktop itself ships a host-side inference engine, Docker Model Runner. It runs
llama.cpp with Metal for GGUF models and, since Docker Desktop 4.62 and after
`docker model install-runner --backend vllm`, MLX safetensors models through
vllm-metal. Containers reach it at `http://model-runner.docker.internal` without any
Compose change. It serves an OpenAI-compatible API under `/engines/v1` (models, chat
completions, completions, embeddings) and a native model API for pulling, listing and
removing models from Docker Hub (`ai/…`) and Hugging Face (`hf.co/…`). The API has no
authentication.

That is a different architecture from the LocalAI image variants: no image to choose,
no generated GPU override, no OIDC login of its own, and an engine whose life cycle
belongs to Docker Desktop, not to the stack.

## Decision

- **A second local inference module, `model-runner`**, next to `localai`, with its own
  Compose profile `model-runner` under `src/ai/model-runner/`. LocalAI is not changed
  and stays the default on Linux.
- **The engine is Docker Desktop's.** The profile carries a single container, a one-shot
  init job (`curlimages/curl`, shaped like `localai-model-init`). The job checks that the
  runner answers, then pulls every entry of `models.txt` through the native model API,
  skipping the ones that are present.
- **`models.txt` is the source of truth** and a render target, so an `overlay/` copy
  survives upgrades. One model reference per line, with an optional alias for LiteLLM.
- **LiteLLM stays the single egress point** and the only way users reach the models. The
  `model_list` entries are rendered from `models.txt` into LiteLLM's configuration, with
  the fixed API base `http://model-runner.docker.internal/engines/v1` and no key. An
  operator overlay still wins over a rendered entry.
- **The default list holds a GGUF embedding model under the alias `nomic-embed-text`**,
  which `RAG_EMBEDDINGS_MODEL` names, so the RAG system and LibreChat's file upload work
  without a manual step. MLX models serve chat only (see *Runner API as verified*).
- **The LocalAI variant catalogue does not change.** `gpu_detect.VARIANTS`, the generated
  LocalAI override and papaia-manager's variant list stay as they are; there is no
  `metal` pseudo-variant.
- **`setup` offers the engines that fit the host.** A detection module next to
  `gpu_detect` checks, during `setup` only, for Darwin on `arm64`, a runner that answers
  `docker model status`, the Docker Desktop version and the engines the runner lists. On
  Apple Silicon with the runner available the runner is the recommended answer and
  LocalAI defaults to off. Every other host sees the question unchanged. The flags are
  `--model-runner` and `--no-model-runner`, sticky like `--local-ai`.
- **Module operations follow the other modules.** Switching the module off removes the
  init job. Deleting its data removes the models listed in `models.txt` through the
  runner's API and never the model store as a whole. Deleting its settings resets
  `models.txt` and the module's `.env`.
- **In a distributed installation the init job is placed with LiteLLM**, because
  `model-runner.docker.internal` resolves only on the machine that runs Docker Desktop.
  The topology validation refuses any other placement, and a node may carry the `gpu`
  hint `apple`.
- **`doctor` and `status` report the runner.** A check reports whether the runner
  answers, whether every listed model is present and which engines it runs, and warns
  when host-side TCP exposes the unauthenticated API. `status` lists the pulled and the
  loaded models. Both use `docker model` on the host and the HTTP API from inside a
  container, so papaia-manager sees the same.
- **Docker Engine on Linux is out of scope.** There the runner listens on
  `model-runner.docker.internal:12434` and needs an `extra_hosts` entry. The detection
  reports the runner as not available on such hosts, and a later decision can add it.

## Consequences

- **Positive**: a Mac runs papAIa's local models on the Apple GPU, in GGUF and MLX
  format, without a hand-built LiteLLM configuration. One line in `models.txt` and a
  `start` add a model. LocalAI, its variants and every Linux installation stay as they
  are.
- **Negative**: the runner's API is unauthenticated and every container on the host can
  reach it, including add-ons. The module therefore keeps host-side TCP off and relies
  on LiteLLM keys and teams for access control; there is no counterpart to the
  `localai-access` role. Pulled models live in Docker Desktop's model store, outside
  Docker volumes, so `papaia-ctl backup` does not contain them and the first `start`
  after a restore pulls them again. vllm-metal is young, Docker's own documentation
  still lags behind its announcement, and its MLX embedding support does not work yet.
- **Neutral**: the stack gains a module whose engine it can neither start nor stop.
  `start` and `stop` only touch the init job, and the runner is switched on and off in
  Docker Desktop's settings. Two local engines can run side by side, each registered in
  LiteLLM under its own model names.

## Runner API as verified

Checked on 2026-11-04 on an Apple Silicon Mac with Docker Desktop 4.95.0, Docker Model
Runner 1.2.6, llama.cpp `b9879-metal` and vllm-metal `v0.2.0`, with `curlimages/curl`
from inside a container against `http://model-runner.docker.internal`:

- `GET /engines/v1/models` answers `{"object":"list","data":[…]}`. Each entry's `id` is
  the normalised reference: `docker.io/ai/smollm2:360M-Q4_K_M`,
  `huggingface.co/mlx-community/qwen2.5-0.5b-instruct-4bit:latest`.
- `GET /models` answers a JSON array of `{id, tags, created, config}` with `config.format`
  (`gguf`, …), the quantisation and the size. `GET /models/<reference>` answers `200` for
  a present model and `404` for a missing one, with the reference written as in
  `models.txt` (`ai/…`, `hf.co/…`). That is the presence check of the init job.
- `POST /models/create` takes `{"from": "<reference>"}` and streams progress as
  `text/plain`, one JSON object per line, HTML-escaped (`&#34;` for `"`). The last line
  has `"type":"success"`. A reference the registry rejects up front returns `500` with a
  plain-text error, but a failure after the stream started (a missing Hugging Face
  repository answers `Unauthorized`) keeps the status `200`. The init job therefore
  checks the last line, not only the status. A repeated pull of a present model answers
  `Using cached model` in about a second.
- `DELETE /models/<reference>` answers `200` and `404` for a missing model. The reference
  needs its registry prefix: `hf.co/mlx-community/…` works, `mlx-community/…` resolves to
  Docker Hub and is not found.
- `GET /engines/status` reports each engine (`llama.cpp`, `vllm`, `mlx`, `diffusers`) as
  `Running: <version>` or `Not Installed`. `GET /engines/ps` lists the loaded models with
  their engine and mode (`completion`, `embedding`).
- `/engines/v1/chat/completions` answers for a GGUF model through llama.cpp and for an
  MLX model through vllm-metal, both addressed by the reference from `models.txt`.
- `/engines/v1/embeddings` returns vectors for the GGUF model `ai/nomic-embed-text-v1.5`.
  Three MLX embedding models (`all-MiniLM-L6-v2-4bit`, `bge-small-en-v1.5-bf16`,
  `nomicai-modernbert-embed-base-4bit` from `mlx-community`) pulled fine, but vllm-metal
  terminated while loading each of them. Hence the GGUF default.
- `docker model install-runner --backend vllm` works on Docker Desktop although its help
  text says "Docker Engine only". The built-in `mlx` engine stays `Not Installed` until
  installed separately and is not needed for MLX models served by vllm-metal.

## Alternatives considered

- **LocalAI's native macOS build, reached from LiteLLM through
  `host.docker.internal:8080`** — rejected as the module: Compose cannot start it,
  `papaia-ctl` cannot manage it, and it needs a second OIDC client. It stays possible by
  hand.
- **A generic "external OpenAI-compatible endpoint" setting** (mlx-lm, LM Studio, Ollama
  with MLX) — rejected as a module: none of them is part of the host's container runtime,
  so the stack could neither pull models nor check them. Registering such a server in
  LiteLLM's Admin UI works today and is documented instead.
- **A `metal` entry in the LocalAI variant catalogue** — rejected: there is no such
  image, and papaia-manager mirrors the catalogue in its contract test, so a fake variant
  would break both sides.
- **Running `docker model pull` from `papaia-ctl` on the host** — rejected: it works on the
  host only, not from papaia-manager, and leaves nothing that `status` can show. The
  native API is reachable from containers, which keeps the Compose idiom.

## References

- #302 (this decision), #303 (module), #304 (LiteLLM registration), #305 (`doctor` and
  `status`), #306 and #307 (documentation), Fidonis/papaia-manager#180
- [ADR 0004](./0004-rag-system-as-optional-core-profile.md), the RAG system as an optional
  core profile and its need for an embedding model
- [ADR 0009](./0009-place-services-on-nodes-with-a-topology-block.md), placement of services
  on nodes
- `docs/architecture.md`, "Local-first inference"
- Docker Model Runner: https://docs.docker.com/ai/model-runner/
