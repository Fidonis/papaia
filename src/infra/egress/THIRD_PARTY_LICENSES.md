# Third-party components of papaia-egress

This file is part of the image `ghcr.io/fidonis/papaia-egress` and lies there at
`/usr/share/licenses/papaia-egress/THIRD_PARTY_LICENSES.md`, next to the license of
papAIa (`LICENSE`, MIT).

The image holds one program of this repository, `/opt/papaia-egress/egress.py`, which uses
the Python standard library only. It is copied onto an unmodified base image; nothing
else is installed.

| Component | Version | License | Full text in the image |
|---|---|---|---|
| Base image `python:3.12.16-slim-trixie` (`sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b`) | 3.12.16 | see the rows below | |
| CPython | 3.12.16 | Python-2.0 (PSF-2.0 and the earlier Python licenses) | `/usr/share/licenses/papaia-egress/texts/Python-2.0.txt` |
| Debian 13 (trixie) packages of the base image | as installed (`dpkg-query -W`) | per package, among them GPL-2.0, GPL-3.0, LGPL-2.1, MIT and BSD licenses | `/usr/share/doc/<package>/copyright` |

The Debian packages are used as installed by the base image, unmodified; their sources
are published by Debian (<https://sources.debian.org/>).
