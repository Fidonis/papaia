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
Configure the TTS server through the new render target `ai/voice/chatterbox.yaml`.
German is the default (`languageSTT: de-DE`, TTS `generation_defaults.language: de`);
users change language, voice and engines per account in LibreChat.

Security posture:

- The STT engine requires a bearer key (`VOICE_API_KEY`, generated on setup and synced
  to `ai/litellm/.env`), covering every route including `/health`.
- The TTS server's auth settings are non-functional placeholders upstream, so it runs
  unauthenticated behind the network boundary — the same deliberate exception the stack
  already makes for LibreChat's MongoDB. Its web UI cannot be disabled; it is simply
  unreachable from outside `papaia-net`.
- **Residual risk, accepted:** the TTS server exposes zero-shot voice cloning (a caller
  can upload reference audio and synthesize that voice). Within `papaia-net` that is
  reachable by other core containers, including the Firecrawl playwright renderer. The
  configuration pins one shipped sample voice and nothing in the stack calls the
  cloning endpoints; a compromised container inside the network could. Voice biometrics
  are special-category data, so the README tells operators to record the feature in
  their processing register.
- Model downloads happen once, from huggingface.co, with HF telemetry disabled and
  the flaky Xet transfer path turned off — the single documented exception to the
  one-egress-point rule, and avoidable by pre-seeding the cache volumes (air-gap
  path in the README). The STT engine serves only models installed through its
  API, so a one-shot `speaches-model-init` container (localai-model-init
  precedent) installs the configured model after the engine is healthy.

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
- CPU-only text-to-speech may be slower than real time; LibreChat plays audio sentence
  by sentence but silently stops a stream that stalls 15 s, so the README documents the
  browser-engine fallback and the GPU option. Speech-to-text is unaffected (turbo
  Whisper at int8 transcribes dictation-length audio in seconds).
- Audio output carries Resemble's Perth watermark — generated speech stays
  identifiable, which supports rather than hurts the sovereignty pitch.
- Both upstreams carry maintenance risk: Resemble has archived the Chatterbox repo
  (MIT, "no support"), and the devnen server pins its fork at a moving branch —
  mitigated by digest-pinned images; a later swap stays behind the stable
  `voice-stt`/`voice-tts` route names.
- The model caches (~5 GB, re-downloadable) live in named volumes and therefore land
  in every `papaia-ctl backup`. Accepted for now; a volume-level backup opt-out is a
  follow-up.
- A GPU variant for the TTS container follows later, generalizing the LocalAI override
  mechanism; nothing in this decision blocks it.
