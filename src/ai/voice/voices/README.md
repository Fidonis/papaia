# German reference voices

The TTS engine (Chatterbox Multilingual) is a zero-shot voice cloner: the
timbre and accent of its output follow the reference clip named in the
request. The voices shipped inside the server image are English recordings,
so German replies synthesized with them carry an English accent — these two
clips give the stack native German voices out of the box. Both are mounted
read-only into the engine's predefined-voices directory alongside the
built-in set (see `docker-compose.yml`).

| File | Speaker (pseudonym) | Source recording | License |
|---|---|---|---|
| `Hokuspokus.wav` | "Hokuspokus" (female) | [Der Horla (Guy de Maupassant), LibriVox](https://archive.org/details/horla_hok_librivox), section 1 | Public domain (LibriVox) |
| `Karlsson.wav` | "Karlsson" (male) | [Der Sandmann (E. T. A. Hoffmann), LibriVox](https://archive.org/details/sandmann_1308_librivox), section 1 | Public domain (LibriVox) |

Each clip is an 18–19 s continuous-speech excerpt, converted to mono 16-bit
WAV and loudness-normalized to −20 LUFS. [LibriVox](https://librivox.org/)
recordings are released into the public domain by their readers; the readers
are credited here by the pseudonyms they publish under, as LibriVox asks.

To add another voice, put a 10–30 s clean mono recording of the target
speaker here (any common sample rate), mount it like the two above, and list
the filename in the LibreChat fragment (`integration/ai/librechat/`) so users
can pick it. Note the GDPR angle documented in ADR 0011: a voice is personal
data, so clone only voices whose speaker has consented or whose recording is
free of such claims — like these public-domain audiobook narrations.
