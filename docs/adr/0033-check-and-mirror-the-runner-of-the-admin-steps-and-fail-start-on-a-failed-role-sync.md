---
adr: 0033
title: Check and mirror the runner of the admin steps like an installed image and fail start on a failed role sync
status: Proposed
date: 2026-11-26
deciders:
  - WilhelmSebastian
tags:
  - security
  - supply-chain
  - keycloak
supersedes: null
superseded_by: null
---

# 0033. Check and mirror the runner of the admin steps like an installed image and fail start on a failed role sync

## Context

The bundled Keycloak publishes no host port. On the host, the steps that call its admin API
(`keycloak-role-sync`, `realm-sync`, `realm-keys-apply`, `post-restore`, the service
accounts and the clients of an add-on) therefore run in a one-shot container on the stack
network (`tools/lib/keycloak_admin_path.py`). Its image is the pin of the service
`papaia-manager` in `src/manager/docker-compose.yml`, because that image carries the
runtime papaia-ctl needs.

That container ran outside every rule an installed image follows:

- The image check of `start`, `upgrade` and `restore` lists the images of the Compose
  project the installation runs. The manager's service has the profile `manager`, so on most
  hosts the runner image was in no check, and the bill of materials of such an installation
  did not list it.
- `PAPAIA_IMAGE_MIRROR` is applied to the Compose project through a generated override; the
  runner was started with the image name of the compose file. A host that pulls through a
  mirror, or that has no access to the published registry, could not start it.
- `start` reported a failed role sync as a warning and ended with `start complete.`. The
  realm then lacks the clients, roles and rights of the core and the modules, and every
  later step fails for a reason that looks unrelated.

## Decision

The one-shot runner of the admin steps is an installed image for the image check, the mirror
and the bill of materials.

- **One function names it.** `keycloak_admin_path.installed_images(repo_root, root)` returns
  the runner image (as the compose file pins it, without the mirror) whenever the
  installation uses the host admin path: the bundled Keycloak (`AUTH_PROVIDER`
  `internal_keycloak`) without a published port. With direct port access and the
  `keycloak` profile, or with another identity provider, it returns nothing.
- **Checked like every image.** The image check (`image-verify`) adds that image to the
  core's list with every command: `start`, `upgrade` (stage 0 and the second phase),
  `restore` (before `post-restore`) and the add-on commands, whose clients step runs in the
  runner too. It must be listed in the bill of materials with the same digest and carry a
  signature by its key; otherwise the command stops before the first container, with the
  image and the reason. `--insecure-images` counts it among the images it skips.
- **Listed in the bill of materials.** `installation-images` prints the images an
  installation runs from the tree (the Compose project its profiles enable, the
  accelerator images of its variants and the runner); a bill of materials of that
  installation is generated from this list. A module image that is published only on the
  release day stays listed in `compat/release-day-images.yaml`, as today.
- **Mirrored like the Compose services.** `runner_image(repo_root, root)` puts
  `PAPAIA_IMAGE_MIRROR` in front of the pin, exactly as the mirror override does for the
  Compose services (`images.mirrored`); the digest stays, so the container runs the checked
  reference by digest. An invalid mirror stops the step.
- **The runner keeps its restrictions.** Read-only root file system, no capabilities, no
  Docker socket, the host user, the stack network only. The mirror changes the registry,
  never the digest.
- **A failed role sync fails `start`.** After `docker compose up`, `start` runs every step
  and then ends with exit code 3, the cause and the retry command on standard error, and no
  `start complete.` line when a step that creates clients, roles or rights failed. `upgrade`
  and `restore` start the stack through `start` and fail with it. A distributed `start`
  fails the same way when the role sync fails on Keycloak's node. Per step:

  | Step | Creates | On failure |
  |---|---|---|
  | `keycloak-role-sync` | the realm's clients, roles, scopes and rights | `start` fails; retry `papaia-ctl keycloak-role-sync` |
  | `replay-chat-sync` | the database role papaia-replay reads the chat with | `start` fails; retry `papaia-ctl start` |
  | `model-keys-sync` | the model keys of the modules, and deletes revoked keys | `start` fails; retry `papaia-ctl start --addons` |
  | restart of an add-on with a new model key | the add-on's containers with the new key | `start` fails and names the add-on; retry `papaia-ctl start --addons` |
  | `npm-provision` | the proxy hosts of the edge, no identity object | warning, as before |

  Every step decides its own outcome with an explicit check of its exit status, not
  through errexit: bash ignores `set -e` in a function that runs as the condition of `if`
  or on the left of `||` and `&&`, so a step that relies on errexit there would fail open.
  An add-on that cannot be started again does not stop the restart of the next one.

## Consequences

- **Positive**: no container of the installer runs from an image that no check covered. A
  host with a mirror pulls the runner through it. A realm without its clients is reported
  where it happens, not by the next module that cannot sign in.
- **Negative**: the bill of materials of an installation on the host admin path must list
  the manager image even when the manager profile is off. A slow Keycloak, chat database or
  model gateway now fails `start` instead of warning; the retry command is printed.
- **Neutral**: the admin steps that an operator runs on their own (`keycloak-role-sync`,
  `realm sync`, `realm keys apply`, `post-restore`, `service-account`) run the runner the
  checkout pins, the same pin every `start`, `upgrade` and `restore` of that checkout
  checks. A tree without `src/manager/docker-compose.yml` names no runner; its admin steps
  then refuse to start one.

## Alternatives considered

- **Run the admin steps in another image the installation always runs.** It would need
  python3 and PyYAML in a service image and a second runtime for the same code. Possible
  later; larger now.
- **Always pull the runner from the published registry.** A release-day image does not
  resolve there before the release, and an installation without access to it has no such
  registry. Rejected.
- **Keep the warning.** The installation reports success with missing clients. Rejected.
