# Security policy

We take the security of papAIa seriously. Thanks for helping us keep it safe.

## Supported versions

Security fixes are issued for the latest published release.
Older releases receive only critical-severity fixes on a best-effort basis.

| Version | Status |
|---|---|
| Latest release | supported |
| Older releases | critical fixes only |

## Reporting a vulnerability

**Do not open a public issue for security problems.**

Please report vulnerabilities through GitHub's
[Private Vulnerability Reporting](https://github.com/Fidonis/papaia/security/advisories/new).
This routes the report directly to the maintainers in a private advisory.

If for some reason you cannot use the private reporting flow, contact
the maintainers at `security@fidonis.de` and we will open the private
advisory on your behalf.

Please include:

- A clear description of the vulnerability and its impact
- Steps to reproduce (a minimal proof of concept is ideal)
- The version / commit affected
- Any suggested mitigation or fix, if you have one

## What to expect

- **Acknowledgement** within 3 working days of your report.
- **Initial triage** (severity assessment, confirmation, scope) within
  10 working days.
- **Coordinated disclosure**: once a fix is ready, we publish a GitHub
  Security Advisory and a patched release. Embargo periods are agreed
  with the reporter on a case-by-case basis; 90 days is the default
  upper bound.
- **Credit**: with your permission, your name (or handle) is listed in
  the advisory and the release notes.

## Out of scope

- Vulnerabilities in the third-party services bundled or integrated by
  papAIa (Keycloak, LiteLLM, LibreChat, Paperless-ngx, n8n, SearXNG,
  etc.) — please report those to the respective upstream project. We will
  ship updated service versions as soon as fixes are available.
- Issues that require attacker-level access to the host running papAIa
  (host compromise is out of scope for the application layer).
- Denial of service via resource exhaustion of the underlying Docker host.

Anything else, including authentication and authorisation bypass, token
leakage, SSRF, privilege escalation within the stack, or insecure default
configuration, is in scope and we want to hear about it.