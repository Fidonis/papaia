# Third-party components of papaia-audit

This file is part of the image `ghcr.io/fidonis/papaia-audit` and lies there at
`/usr/share/licenses/papaia-audit/THIRD_PARTY_LICENSES.md`, next to the license of
papAIa (`LICENSE`, MIT).

The image holds the package `papaia_audit` of this repository and the Python packages
below, installed unmodified from the wheels pinned by hash in
`src/infra/audit/requirements.txt`. They lie under `/usr/local/lib/python3.12/site-packages/`,
each with its license files in `<package>-<version>.dist-info/licenses/`. The libraries are
loaded by the Python process (dynamic linking); none is changed.

| Component | Version | License | Full text in the image |
|---|---|---|---|
| Base image `python:3.12.16-alpine3.24` (`sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89`) | 3.12.16 | see the rows below | |
| CPython | 3.12.16 | Python-2.0 (PSF-2.0 and the earlier Python licenses) | `/usr/share/licenses/papaia-audit/texts/Python-2.0.txt` |
| Alpine Linux 3.24 packages of the base image (musl, OpenSSL, among others) | as installed (`apk info`) | per package, among them MIT, Apache-2.0, GPL-2.0 and BSD licenses | sources and license data published by Alpine Linux (<https://pkgs.alpinelinux.org/>) |
| psycopg | 3.3.8 | LGPL-3.0-only | `psycopg-3.3.8.dist-info/licenses/LICENSE.txt` |
| psycopg-binary | 3.3.8 | LGPL-3.0-only | `psycopg_binary-3.3.8.dist-info/licenses/LICENSE.txt` |
| libraries bundled in the psycopg-binary wheel (`psycopg_binary.libs/`): libpq, OpenSSL, MIT Kerberos, OpenLDAP, Cyrus SASL, keyutils, com_err | as bundled by psycopg-binary 3.3.8 | PostgreSQL, Apache-2.0, MIT, OLDAP-2.8, BSD-style (Cyrus SASL), LGPL-2.1-or-later, MIT | published with the sources of psycopg-binary and of each library |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause | `cryptography-50.0.2.dist-info/licenses/` |
| GCC runtime library bundled in the cryptography and rpds-py wheels (`libgcc_s`) | as bundled | GPL-3.0-or-later WITH GCC-exception-3.1 | published with the sources of GCC |
| cffi | 2.1.1 | MIT-0 | `cffi-2.1.1.dist-info/licenses/LICENSE` |
| pycparser | 3.12 | BSD-3-Clause | `pycparser-3.12.dist-info/licenses/LICENSE` |
| jsonschema | 4.26.0 | MIT | `jsonschema-4.26.0.dist-info/licenses/COPYING` |
| jsonschema-specifications | 2025.9.1 | MIT | `jsonschema_specifications-2025.9.1.dist-info/licenses/COPYING` |
| referencing | 0.37.0 | MIT | `referencing-0.37.0.dist-info/licenses/COPYING` |
| attrs | 26.1.0 | MIT | `attrs-26.1.0.dist-info/licenses/LICENSE` |
| rpds-py | 2026.9.1 | MIT | `rpds_py-2026.9.1.dist-info/licenses/LICENSE` |
| typing-extensions | 4.16.0 | PSF-2.0 | `typing_extensions-4.16.0.dist-info/licenses/LICENSE` |

psycopg is used as an unmodified library; under LGPL-3.0 its sources are those of the
pinned release (<https://github.com/psycopg/psycopg>), and the image may be rebuilt with
another version of it by changing `requirements.txt`.
