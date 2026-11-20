---
adr: 0011
title: Offer local voice (STT and TTS) as an optional core profile
status: Proposed
date: 2026-11-11
deciders:
  - WilhelmSebastian
tags:
  - voice
  - speech
  - librechat
  - litellm
  - core
  - addon-contract
  - licensing
supersedes: null
superseded_by: null
---

# 0011. Offer local voice (STT and TTS) as an optional core profile

## Context

The stack has no speech capability: LibreChat ships a `speech` panel, but without
configured engines it falls back to the browser's Web Speech API — which on most
platforms is a cloud service of the browser vendor, the opposite of the data-sovereignty
promise (architecture.md, principle ①). Spoken interaction with the stack ("talk to your
documents") is a core demo scenario and a real accessibility feature, and the engines
should also be callable outside LibreChat — by automations, agents or a customer's own
web app.

Three decisions had to be made: where the capability lives (core profile vs. add-on),
which engines qualify, and how callers reach them.

**Core profile, not an add-on.** The LibreChat speech configuration is part of the
core's `librechat.yaml`; an add-on cannot layer a fragment onto it without the core
shipping the engines anyway. The RAG system set the precedent (ADR 0004): a module of
core-adjacent services toggled by one Compose profile, with integration fragments merged
only while the profile is active.

**Engine choice is constrained by licensing.** The project accepts copyleft components
only as unmodified network services (THIRD_PARTY_LICENSES.md). That ruled out the
otherwise obvious candidates:

- **Piper** — today maintained as `piper1-gpl` (GPL-3.0); every distribution, older
  MIT-labelled ones included, bundles espeak-ng (GPL-3.0) for phonemization.
- **openedai-speech** — AGPL-3.0 and archived upstream.
- **Coqui XTTS-v2** — model weights under CPML (non-commercial).
- **Kokoro** — Apache-2.0, but German only via a community pipeline that again needs
  espeak-ng.
- **chatterbox-tts-api (travisvn)** — AGPL-3.0, Docker images 17 months stale, returns
  WAV only (LibreChat's streaming player handles only MP3), and its multilingual mode
  is broken on non-CUDA machines.

What remains, with German support and clean licenses end to end:

- **STT: speaches** (MIT) — faster-whisper behind an OpenAI-compatible API, with
  per-request model loading, idle unloading and bearer-key auth. Default model
  `deepdml/faster-whisper-large-v3-turbo-ct2` (explicitly MIT; the equivalent Systran
  upload declares no license). The speaches *image* bundles piper-tts, phonemizer and
  espeak-ng (GPL-3.0) and Ubuntu's ffmpeg — unused by our configuration and covered by
  the network-service rule the licenses file already applies to boky/postfix.
- **TTS: Chatterbox Multilingual** (Resemble AI, MIT — code, weights and the embedded
  Perth watermarker) served by **Chatterbox-TTS-Server (devnen)** (MIT), which exposes
  `/v1/audio/speech` with selectable output format and ships prebuilt CPU images.

**Callers reach the engines through LiteLLM.** The routes `voice-stt`
(`mode: audio_transcription`) and `voice-tts` (`mode: tts`) are appended to LiteLLM's
`model_list` by a profile fragment. That gives external callers the existing endpoint,
key management and spend tracking, keeps the engines unpublished, and LibreChat's
speech panel uses the same routes with the key it already holds — no second egress
point, consistent with "one egress point" in the architecture.

## Decision

Add the Compose profile `voice` (module directory `src/ai/voice/`) with two internal
services, `speaches` and `chatterbox`, both digest-pinned CPU images without published
ports. Toggle it with `papaia-ctl setup --voice/--no-voice` like the other modules.
Merge two fragments while the profile is active: a `speech` block into
`ai/librechat/librechat.yaml` and the two model routes into `ai/litellm/config.yaml`.
The audio routes are marked undiscoverable, and a small proxy hook
(`ai/litellm/papaia_hooks.py`) hides such deployments from the model listings for
*every* key — LiteLLM's own flag spares admin keys, LibreChat holds the master key,
and a transcription route offered as a selectable chat model would fail on the first
message. Hiding is presentation-only; the routes stay fully callable.
Configure the TTS server through the new render target `ai/voice/chatterbox.yaml`.
German is the default (`languageSTT: de-DE`, TTS `generation_defaults.language: de`);
users change language, voice and engines per account in LibreChat.

Two findings from running the stack shape the defaults:

- **The bundled chatterbox package cannot load the multilingual checkpoints
  without CUDA**: two of its `torch.load` calls pass no `map_location`, and the
  published checkpoints carry CUDA storages. The fix was still an unmerged PR when
  Resemble archived the repository, and the server's fork has not picked it up. The
  Compose service therefore starts the server through a small wrapper that defaults
  `map_location` to the CPU when CUDA is unavailable — verified to load and
  synthesize correctly; remove it when a fixed image appears.
- **CPU synthesis is slower than real time** (measured well above RTF 1 even before
  emulation overhead is discounted), and LibreChat silently stops a playback stream
  that stalls 15 s. Spoken replies therefore default to the **browser** TTS engine;
  the external engine stays fully wired and is a per-user switch in Settings →
  Speech, with the accelerator images (`setup --voice-variant`) as the way to
  make the local voice fast enough for live playback. STT is unaffected and
  defaults to the local engine. Callers on the `voice-tts` route
  (no playback timeout) can use the slow synthesis as is.

Security posture:

- The STT engine requires a bearer key (`VOICE_API_KEY`, generated on setup and synced
  to `ai/litellm/.env`), covering every route including `/health`.
- The TTS server's auth settings are non-functional placeholders upstream, so it runs
  unauthenticated behind the network boundary — the same deliberate exception the stack
  already makes for LibreChat's MongoDB. Its web UI cannot be disabled; it is simply
  unreachable from outside `papaia-net`. Its config file is mounted read-only so the
  unauthenticated settings endpoints cannot persist attacker-chosen settings into the
  rendered file on the host (saving through its UI fails, which is accepted).
- **Residual risk, accepted:** the TTS server exposes zero-shot voice cloning (a caller
  can upload reference audio and synthesize that voice). Within `papaia-net` that is
  reachable by other core containers, including the Firecrawl playwright renderer. The
  configuration offers a fixed set of predefined voices — two public-domain German
  audiobook narrations the module ships (`src/ai/voice/voices/`, cloning a reference
  voice copies its accent, so German output wants a German reference) next to the
  image's English samples — and nothing in the stack calls the cloning endpoints; a
  compromised container inside the network could. Voice biometrics
  are special-category data, so the README tells operators to record the feature in
  their processing register. The shipped clips are narrations by identifiable
  LibriVox readers: public domain covers the recordings, while personality rights
  over a cloned voice are a younger question — `src/ai/voice/voices/README.md`
  spells out the consideration and the one-file swap for deployments that would
  rather clone a consented in-house recording.
- Model downloads happen once, from huggingface.co, with HF telemetry disabled and
  the flaky Xet transfer path turned off — the single documented exception to the
  one-egress-point rule, and avoidable by pre-seeding the cache volumes (air-gap
  path in the README). The STT engine serves only models installed through its
  API, so a one-shot `speaches-model-init` container (localai-model-init
  precedent) installs the configured model, retrying until the engine answers
  (deliberately not gated on the engine's healthcheck, which fails by design on
  an empty API key — the compose file explains the trade-off).

Contract surface: the two services are attachable (`networks.attach`) and the TTS
config is a render target, so `ADDON_API` moves to generation 5 (additive; `min`
stays 1).

## Consequences

- Spoken chat works end to end on customer hardware; the demo story "talk to your
  documents, nothing leaves the house" holds, with the transcript-retention caveat
  documented (transcripts become ordinary chat messages in MongoDB/Meilisearch).
- ~6 GB additional resident RAM while the profile is on — the TTS model never unloads.
  `mem_limit` (default 8g) contains an OOM to the TTS container. Hosts at the 8 GB
  baseline cannot run the profile; the README says so.
- Spoken replies in LibreChat use the browser voice until a user opts into the
  external engine, so the out-of-the-box replies are not watermarked and, on many
  platforms, use a browser-vendor cloud voice — the README states both. Speech-to-text
  is local from the start (turbo Whisper at int8 transcribes dictation-length audio
  in seconds).
- Audio output carries Resemble's Perth watermark — generated speech stays
  identifiable, which supports rather than hurts the sovereignty pitch.
- Both upstreams carry maintenance risk: Resemble has archived the Chatterbox repo
  (MIT, "no support"), and the devnen server pins its fork at a moving branch —
  mitigated by digest-pinned images; a later swap stays behind the stable
  `voice-stt`/`voice-tts` route names.
- The model caches (~5 GB, re-downloadable) live in named volumes and therefore land
  in every `papaia-ctl backup`. Accepted for now; a volume-level backup opt-out is a
  follow-up.
- The TTS container has accelerator variants from the start: upstream publishes
  CUDA-12.8 and ROCm builds of the pinned commit, and `setup --voice-variant`
  selects one through a generated override in `$PAPAIA_CONFIG_DIR/overrides/` —
  the LocalAI mechanism generalized as planned, with the image pins kept in the
  voice compose file so release bumps carry through. The rendered TTS config says
  `device: auto`, which resolves to the CPU or the GPU depending on the image.
