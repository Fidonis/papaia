---
adr: 0014
title: Keep governance metadata in a separate operator file and report model policy findings
status: Proposed
date: 2026-11-14
deciders:
  - WilhelmSebastian
tags:
  - knowledge-map
  - governance
  - data-protection
supersedes: null
superseded_by: null
---

# 0014. Keep governance metadata in a separate operator file and report model policy findings

## Context

After ADR 0013 the map knows every source, server and agent an installation
can reach. Operators asked the next question: *which* of these hold
confidential or personal data, and which model may see their content? The
map is the only place where three facts meet that no single system sees
together: how sensitive a source is, how widely it is visible, and which
model tier an agent or the vector index sends its content to.

Four constraints shape the design:

- The value lies in checking the wiring, not in a second documentation
  system. Operators already keep records of processing, risk registers and
  asset lists in their own tools; fields that duplicate them stay empty and
  turn every entry into a reminder nobody acts on.
- Governance data is not model-facing. Only a short handling label is useful
  in a manifest the navigator reads.
- Add-ons know their data best but must not decide its classification: the
  operator carries the responsibility, so an add-on may only suggest.
- The map cannot enforce. Data access is decided by the target systems (with
  the user's token), model use by LiteLLM teams/keys and the agents' model
  bindings in the chat client. A map that claimed protection would be wrong
  and would invite operators to rely on it.

## Decision

1. **Separate, small operator file.** `overlay/knowledge-map/governance.yaml`
   (optional) holds per-entry `sources` records (`owner` role,
   `classification`, `personal_data`, optional `data_subjects` and
   `ropa_ref`), `models` with their tier (`local`, `eu_hosted`,
   `third_country_contracted`, `third_country`) and optional role, `policy`
   (allowed tiers per classification and per category of personal data,
   broad roles, the embedding model) and time-boxed `exceptions` (`finding`,
   `subject`, `expires`, optional `reason`, `accepted_by_role` and `risk_ref`
   into the operator's risk register). Nothing else: purposes, retention and review dates stay in
   the tools that already keep them. Shape errors refuse the render, unknown
   keys are low findings.
2. **Overrides and declarations stay out.** A `governance` key in
   `overrides.yaml`, or governance fields in a declaration or override, are
   render errors. A declaration may carry a `governance_proposal`
   (classification, personal data, data subjects) that the operator confirms.
3. **Fail-closed evaluation.** For the checks, an unclassified entry counts
   as the stricter of its proposal and `internal` — an add-on cannot declare
   itself public — and as `confidential` without a proposal. Personal data
   defaults to `unknown`; a model not listed under `models` counts as
   `third_country`.
4. **Manifests get the handling label only.** Each manifest carries
   `handling: {classification, personal_data}` with the values the operator
   confirmed (`unclassified`/`unknown` otherwise). No proposal, owner,
   reference or policy reaches a manifest or the index, and proposals do not
   change the content hash.
5. **Inventory facts stay internal.** The renderer notes an agent's model and,
   per server, whether it is selectable in free chat (`chatMenu`) and whether
   it uses a credential that is the same for every user. These feed the
   checks and the findings but are not written into manifests; the credential
   value is never read.
6. **Findings with a fix, not enforcement.** Each render adds governance
   findings to `lints.yaml`: model tiers the policy does not allow for what an
   agent or the embedding step reaches, unlisted models, servers selectable in
   free chat or using a shared credential in front of sensitive data,
   sensitive copies in the vector index, confidential or special data open to
   everyone, undocumented personal data, record references missing once the
   operator uses them, classification below the proposal, and one bundled
   `classification_open` reminder instead of one finding per unclassified
   entry, and external Agent2Agent targets nobody has documented. Every
   finding carries `origin: render`, a `category` and a concrete `fix`;
   nothing is changed automatically. An active exception marks its finding as
   accepted risk through its `expires` day; from the day after, the finding
   returns together with `exception_expired`.

## Consequences

- The management view can show policy findings next to the map's quality
  lints and pass high ones on through its existing notifications; a fact
  export can feed the operator's own inventory and records tools.
- Wording stays honest: findings are "policy findings" with an action level
  and support documentation duties; nothing is called compliant or enforced.
  The docs name where enforcement lives — user tokens for MCP servers, LiteLLM
  teams and model access groups per agent, `chatMenu: false` for servers that
  reach confidential data — and recommend switching routing telemetry off for
  professions bound by professional secrecy.
- Fail-closed defaults make a fresh installation show its gaps on purpose;
  bundling the classification reminder keeps that to one finding.
- The map server mounts only the gold set of the operator directory, so it
  never sees governance.yaml or the overrides; its manifest sanitising still
  strips governance keys as a second line.
- Inventoried server and agent entries inherit the roles of the sources they
  reach, so the inventory cannot reveal a hidden source.
- `lints.yaml` carries the effective policy, the codes an exception may name,
  an agent table (model, tier, reached entries, result) and structured
  `params` per finding, so the management view displays what the renderer
  computed instead of re-implementing the rules.

## Alternatives considered

- **A full documentation schema (system profile, purposes, retention,
  review cycles).** Duplicates the operator's existing GRC, wiki and data
  protection tools and stays empty in practice; rejected in favour of
  references (`ropa_ref`, `risk_ref`).
- **Governance fields in `overrides.yaml`.** One file fewer, but mixes
  model-facing corrections with internal records and lets the override merge
  push governance data into manifests; rejected.
- **Add-on declarations set the classification.** The software vendor cannot
  carry the operator's responsibility; reduced to a proposal.
- **Block the render on policy findings.** Would turn documentation gaps into
  outages and still not enforce anything at runtime; rejected in favour of
  findings with fixes and time-boxed exceptions.

## References

- ADR 0011, ADR 0012, ADR 0013
- Regulation (EU) 2016/679, Art. 9, 10, 30
- ISO/IEC 27001:2022, Annex A 5.9, 5.12
