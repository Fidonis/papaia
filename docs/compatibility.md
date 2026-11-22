# Compatibility and suite bill of materials

A papAIa **suite** is one tested combination of the core, papaia-manager, the
modules and the first-party add-ons. Two files describe it:

- the **compatibility matrix** [`compat/suite.yaml`](../compat/suite.yaml), shipped
  with the core and evaluated by `papaia-ctl addon check`;
- the signed **suite bill of materials** `compat/suite-<version>.yaml` with its
  signature `compat/suite-<version>.yaml.sig`, added to the release tag of the
  core and checked with `papaia-ctl suite verify`.

## Compatibility matrix

One row per suite. Each cell is the version range of that component which was
tested with the suite; `–` means the component is not part of the suite.
*Add-on API* is the add-on contract window (`ADDON_API`, see
[ADR 0002](adr/0002-addon-core-compatibility-gating.md)) the suite's core serves.
A `candidate` row describes a suite whose release is still being prepared.

| Suite | Status | Core | Add-on API | Manager | Me | Studio | Data | Flow | Assistant | Paperless |
|---|---|---|---|---|---|---|---|---|---|---|
| 1.9.0 | released | `>=1.9.0,<1.10.0` | 1..6 | `>=1.7.0,<1.8.0` | – | – | – | – | – | `>=2.0.0,<3.0.0` |
| 1.10.0 | candidate | `>=1.10.0,<1.11.0` | 1..13 | `>=1.8.0,<1.9.0` | `>=0.1.0,<0.2.0` | `>=0.2.0,<0.3.0` | `>=0.1.0,<0.2.0` | `>=0.1.0,<0.2.0` | `>=0.1.0,<0.2.0` | `>=2.0.0,<3.0.0` |

Columns map to add-on names: Me `papaia-me`, Studio `papaia-studio`, Data
`papaia-data`, Flow `papaia-flow`, Assistant `papaia-assist`, Paperless
`paperless`. The manager is part of the core and pinned in
`src/manager/docker-compose.yml`.

### How `papaia-ctl addon check` uses it

```sh
tools/papaia-ctl addon check                         # against this checkout
tools/papaia-ctl addon check --target-core=../next   # against an upgrade candidate
```

For every active add-on that the matrix names, the add-on version must lie in
its cell of the core's suite **or of the suite before it**: core N accepts the
add-ons of suites N and N-1, as long as the add-on contract window fits too.
Otherwise the add-on is reported `INCOMPATIBLE` on the `matrix` axis and the
command exits 2 (in `warn` mode or with `--force` it only warns). A malformed
matrix is always an error. A core without `compat/suite.yaml` (1.9.0 and older
tags) is checked as before, without the matrix. With `--target-core` the matrix
of the candidate is used.

Edge cases:

- A prerelease core (`1.10.0-rc.1`) is judged by the row of its release
  (`1.10.0`).
- If the matrix has no row for the judged core, every add-on it names is
  reported `INCOMPATIBLE` on the `matrix` axis: the check fails closed. This
  happens with `--target-version` for a version the current matrix does not
  cover; use `--target-core` with the candidate checkout instead.
- With only `--target-addon-api` the core version is unknown; the matrix is
  not applied and each named add-on carries the warning "suite matrix not
  checked".

## Suite bill of materials

The bill of materials (schema `papaia.suite-bom/1`,
[`tools/schemas/suite-bom.schema.json`](../tools/schemas/suite-bom.schema.json))
lists:

- every repo of the suite with role (`core`, `manager`, `module`, `addon`,
  `mcp`, `kit`, `registry`), version, tag `vX.Y.Z`, commit, and where it applies
  the add-on contract generation, minimum core and database schema state;
- every image with tag, digest, SPDX license, license class, SBOM digest and
  delivery (`shipped`, `customer-pulled`, `test-only`; a `delivery` bill of
  materials holds no `test-only` image);
- the number of containers per repo and the totals of containers and distinct
  images;
- in a `delivery` bill of materials at least one module, one add-on repo (the
  Paperless add-on lives there) and both MCP servers (role `mcp`, two entries);
- the checksum of the kit snapshot;
- the contract generation window of the suite;
- the public key the file is signed with and its fingerprint;
- optionally the exchange-right pairings the suite ships with (`pairings:`, each
  `client`, `audience` and `effects` out of `r`, `w`, `d`, `x`, a pair listed once).
  `setup` shows them with the sha256 of the list and confirms only the read pairings;
  a pairing with `w` or `d` waits for a second person (see "Pairing approval" in
  [`architecture.md`](architecture.md)).

The file is signed with an ECDSA P-256 key, as `cosign sign-blob` does with a
key pair. The signature file holds the base64 signature. Real
`cosign sign-blob` output (cosign 2.4.1, `--tlog-upload=false`) is part of the
tests (`tools/tests/fixtures/suite/`). Write the public key as a YAML block
scalar (`public_key: |`) so that it can be found without parsing the file.

### Verify a bill of materials

```sh
tools/papaia-ctl suite verify --bom=compat/suite-1.10.0.yaml --suite=1.10.0   # pinned release key
tools/papaia-ctl suite verify --bom=suite-1.10.0.yaml --suite=1.10.0 --key=release.pub
tools/papaia-ctl suite verify --bom=suite-1.10.0.yaml --suite=1.10.0 \
    --fingerprint=sha256:<fingerprint obtained out of band>
```

**Trust anchor.** The release public key is pinned in the core checkout as
`compat/release-key.pub` and is the default anchor. `--key` or
`--fingerprint` replace it, for example to check against a key obtained out
of band. Do not take the key or fingerprint from the release notes of the
same release: whoever can change the release can change the bill of
materials, its signature and the notes together. Without a pinned key and
without `--key` or `--fingerprint` the command refuses (exit 2). The key inside
the file is never trusted on its own; it must be the anchor key.

**Order of checks.** The file, the signature and the key are read with size
limits, and only from regular files. Then the signature is checked, before
the file is parsed:

- with a key file (pinned or `--key`), against that key;
- with `--fingerprint`, the one `BEGIN PUBLIC KEY` block in the raw bytes is
  located by a bounded pattern, without parsing the YAML; it must hash to the
  fingerprint, and the signature is checked against it. A file with no or more
  than one such block is refused.

Only a file with a valid signature is parsed. Then the structure is checked:
unknown fields are refused, tags must equal the version, commits and digests
must be complete, there is exactly one core, manager and kit, a delivery names
modules, add-ons and both MCP servers, and the totals must equal the entries.
Last, the file is bound to what you expect: scope `delivery` unless
`--scope=test` is given, and the suite given with `--suite`. An older suite
file or a test-scope file signed with the same key is refused that way.

**Always pass `--suite` in scripts.** Without it any suite signed with the
release key passes, including an older one (rollback). The command then warns
on stderr and `--json` reports `"suite_bound": false`. Scripts and automated
checks must pass `--suite=<expected version>`.

A key file with Windows line endings (CRLF) is accepted; it is the same key.

Any change to the file after signing, even one digest, fails the check. The
command exits 0 when the file can be trusted and 2 otherwise; `--json` prints
a summary. `openssl` must be installed (it is already required by `setup`).

The release key is not pinned yet; until `compat/release-key.pub` is added,
pass `--key` or `--fingerprint` with a key obtained out of band.

### Images: checked against the bill of materials before they start

`start` and `upgrade` use the bill of materials of the checkout itself,
`compat/suite-<VERSION>.yaml`, verified like `suite verify --suite=<VERSION>`
with the pinned `compat/release-key.pub` and scope `delivery`. Each image
Compose is about to run must be listed there with the same digest and carry a
cosign signature (`cosign sign --key`, tag `sha256-<digest>.sig`) by the key
of the bill of materials. A bill of materials therefore lists every core
image, the accelerator variants of LocalAI and voice included, with the tag
and digest the compose files pin. An image pinned without a tag
(`compat/image-exceptions.yaml`) is matched by its digest.

An upgrade verifies the target's bill of materials against the release key of
the installed checkout. A release that replaces the key ships
`compat/release-key-rotation.yaml` (schema `papaia.release-key-rotation/1`):
one entry per previous key the release still accepts, each with that key
(`previous_key`, PEM) and its signature over the new `compat/release-key.pub`
(`signature`, `cosign sign-blob --key <previous key> compat/release-key.pub`).
Without an entry for the installed key the upgrade is refused.

A rotation signs the new key file only; it names no suite version and no date.
It therefore cannot be revoked: an entry signed once stays valid in every later
tree that carries it, and a key it vouched for can always be reached again
from the key that signed it. Two rules follow for the release process. A key
that was retired or may be compromised is never rotated to again, and no new
rotation entry is ever signed over it. A compromised key is replaced by a new
key pinned through a release that operators install with a fingerprint
checked out of band, as in the bootstrap case below, not by a rotation.

### Bootstrap: the first upgrade to a pinned key

A core that pinned no release key (1.9.x and older) runs the first phase of
its upgrade itself and hands no anchor to the second phase. On that first
upgrade the second phase checks the images against the key the target brings,
so the target vouches for itself; this cannot be avoided, because there is
nothing installed to vouch for it. The second phase prints the fingerprint of
that key. Before relying on the check, the operator compares it with the
release key fingerprint published for the release, obtained out of band (not
from the release notes of the same release). Every later upgrade is anchored
in the key installed by this one.

Until `compat/release-key.pub` and the bill of materials of a release are part
of the checkout, `start` and `upgrade` refuse unless `--insecure-images` is
given for that one command. See the README section "Image pinning and
signatures".

### Release gate: what every release must deliver for the image check

The check works only with release data the release process produces. A
release (and a hotfix) is not cut until all of the following hold:

1. `compat/release-key.pub` is in the tagged tree; a key change comes with
   `compat/release-key-rotation.yaml` signed by the previous key.
2. `compat/suite-<VERSION>.yaml` and its `.sig` are in the tagged tree, scope
   `delivery`, listing every core image with the tag and digest the compose
   files pin, the accelerator variants of LocalAI and voice and the add-on and
   module images of the delivery included.
3. Every one of those digests is signed with the release key (`cosign sign
   --key`) into the signature repository named by
   [`compat/image-signatures.yaml`](../compat/image-signatures.yaml), i.e. with
   `COSIGN_REPOSITORY=<that repository>`. Third-party images (docker.io,
   quay.io, ghcr.io of other owners) cannot carry a signature in their own
   repository, so the signature location is release data, not operator
   configuration. `PAPAIA_IMAGE_SIGNATURES` exists only for mirrors that keep
   signatures elsewhere.
4. The tag exceptions in `compat/image-exceptions.yaml` are still valid on the
   release date; they expire after at most 90 days and then fail CI on every
   branch, so they are renewed or resolved before that.
5. The own images of the core (next section) are built from the tagged tree,
   pushed to `ghcr.io/fidonis/`, signed like 3, and pinned in compose with
   the release `VERSION` as tag; their entries in the bill of materials come
   from `tools/build-images bom-entries`.

Without 1 to 3 every operator would need `--insecure-images`.

## Own images of the core

A core service that runs code of this repository runs it from an image built
here: `papaia-egress`, `papaia-lifecycle`, `papaia-audit`, `papaia-people` and `papaia-docker-gate` today. A stock image with the code
mounted in, or an image built by Compose (`build:`), is not used: the start
check would have nothing to compare it with. The images are listed in
[`compat/own-images.yaml`](../compat/own-images.yaml) (schema
`papaia.own-images/1`) with their Dockerfile, every file the build may read,
the compose services that run them and their license.

Each Dockerfile starts from a base pinned by tag and digest, copies only the
declared inputs, sets a numeric user other than root and carries the notice
files under `/usr/share/licenses/<image>/`: `LICENSE`,
`THIRD_PARTY_LICENSES.md` (the runtime components) and `texts/` with the full
license texts the base image does not already hold (Debian keeps one copyright
file per package under `/usr/share/doc/`). The label
`org.opencontainers.image.licenses` names the license. `tools/build-images
check` and the test suite enforce these rules, and that the compose services
pin `<name>:<VERSION>@sha256:<digest>`.

A stage that only fetches files for the target may run on the build platform
(`FROM --platform=$BUILDPLATFORM`, the only flag allowed on `FROM`):
`papaia-audit` unpacks the wheels pinned by hash in its `requirements.txt` for
the target platform there, without compiling or running them, and the final
stage copies the result. Both variants are thus built without emulation.

`tools/build-images` takes an image from the checkout to the bill of
materials:

```sh
# 1. Build linux/amd64 and linux/arm64 from the committed inputs and push.
tools/build-images build --registry=<prefix> --out=builds.json
# 2. Sign each digest into the signature repository (behind <prefix>).
COSIGN_PASSWORD=... tools/build-images sign --builds=builds.json --key=<cosign key>
# 3. Pin the digests in compose.
tools/build-images pin --builds=builds.json
# 4. The image entries of the core for the bill of materials.
tools/build-images bom-entries --sbom=ghcr.io/fidonis/papaia-egress=<sbom> ...
```

- `<prefix>` is empty for the release registry, or the prefix of a local
  registry such as `127.0.0.1:5000/unpublished/`. The images then lie under
  `<prefix>ghcr.io/fidonis/<image>`, which is where an installation with
  `PAPAIA_IMAGE_MIRROR=<prefix>` pulls and checks them. The compose files
  always name `ghcr.io/fidonis/<image>`; there is no image name that exists
  only locally.
- The build is reproducible. The context holds only the declared inputs and
  `LICENSE`; timestamps are fixed (`SOURCE_DATE_EPOCH=0`) and no provenance or
  SBOM attestation is added to the index. The same inputs and `VERSION`
  therefore give the same digest on any host and from any later commit, and
  anyone can rebuild a release and compare it with the pin. Inputs with
  uncommitted changes are refused.
- A change to an input (the Dockerfile, the program, its notice), to `LICENSE`
  or to `VERSION` changes the digest: rebuild and pin in the same change.
  The live test `tools/tests/test_own_images_registry.py` fails while the pin
  is stale.
- The signing key is a cosign key file outside the checkout; its passphrase is
  read from `COSIGN_PASSWORD` only. With `--cosign=<binary>` the host's
  registry login is used (release); without it cosign runs as a pinned
  container on the host network (local registry). For a loopback registry the
  signature is not written to the public transparency log.
- CI (`.github/workflows/images.yml`) builds every own image on each pull
  request, push and night into a registry inside the job and scans both
  platforms of the built digest (`tools/scan-images scan`, Trivy pinned by
  digest). The gate: a critical finding always fails; a high finding passes
  only with an unexpired entry in
  [`security/exceptions.yaml`](../security/exceptions.yaml) (at most 90 days,
  approved by the security officer); an expired entry fails. Reports and the
  CycloneDX SBOM of each platform are kept as the `images-report` artefact.
- On a version tag the `publish` job, the only one that may request an OIDC
  token, rebuilds into `ghcr.io/fidonis/`, refuses digests other than the
  compose pins (`tools/build-images verify`; the scan job checked its build
  against the same pins), signs each digest with the workflow identity and
  attaches both SBOMs as cosign attestations of type `cyclonedx`, next to the
  image (`tools/build-images sign-keyless`). The job runs only when the
  repository variable `PAPAIA_PUBLISH_IMAGES` is `true`. The signature by the
  release key in the signature repository (3 of the release gate) stays with
  the release process. Check a released image and fetch its SBOM:

  ```sh
  id='^https://github\.com/Fidonis/papaia/\.github/workflows/images\.yml@refs/tags/v'
  issuer=https://token.actions.githubusercontent.com
  cosign verify --certificate-identity-regexp "$id" \
      --certificate-oidc-issuer "$issuer" ghcr.io/fidonis/papaia-egress@sha256:<digest>
  cosign verify-attestation --type cyclonedx --certificate-identity-regexp "$id" \
      --certificate-oidc-issuer "$issuer" ghcr.io/fidonis/papaia-egress@sha256:<digest> \
      | jq -r .payload | base64 -d | jq .predicate
  ```
- An own image gets no exception at start: it must be listed with its digest
  and signed, like every other image. For a local test environment that means
  the local registry, its test key, and a test bill of materials signed with
  that key.

