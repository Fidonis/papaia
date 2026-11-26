"""Files a root run of papaia-ctl writes in a configuration directory of another account.

A second host account approves a write pairing with `sudo tools/papaia-ctl pairing
approve` (lib/pairing_approval.py), so papaia-ctl then runs as root in a configuration
directory that belongs to the account that set the installation up. Root must neither
follow a link that account could plant nor leave a file behind that the account's own
runs (the realm sync at `start`) can no longer open. Everything here works on directory
descriptors:

- the configuration directory is opened without following a symbolic link and must not be
  writable by group or others; its owner (uid and gid) is the owner of everything written
  below it;
- every folder below it is opened relative to its parent, never through a symbolic link;
  one that does not exist is created 0700 and handed to that owner;
- a file is opened relative to its folder, never through a symbolic link. A new one is
  created 0600 and handed to that owner before anything is written to it; an existing one
  must be a regular file of that owner with exactly one link (a hard link would let root
  write to, or hand over, a file elsewhere).

Nothing here decides who may change what: the callers keep their own rules.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_WRITABLE = stat.S_IWGRP | stat.S_IWOTH


class OwnerError(Exception):
    """A folder or file that a root run must not trust or write; nothing was written."""


def owner_of(st: os.stat_result) -> tuple[int, int]:
    """(uid, gid) of the configuration directory: the owner of what a root run writes."""
    return st.st_uid, st.st_gid


def open_config_dir(path: Path) -> tuple[int, tuple[int, int]]:
    """The configuration directory as a descriptor and its owner. A symbolic link, a
    missing directory or one that group or others may write is refused."""
    try:
        fd = os.open(path, DIR_FLAGS)
    except FileNotFoundError:
        raise OwnerError(f"{path} does not exist") from None
    except OSError as exc:
        raise OwnerError(
            f"{path} cannot be opened as a directory of its own (a symbolic link is "
            f"refused when papaia-ctl runs as root): {exc.strerror}"
        ) from None
    st = os.fstat(fd)
    if st.st_mode & _WRITABLE:
        os.close(fd)
        raise OwnerError(f"{path} is writable by group or others (chmod go-w)")
    return fd, owner_of(st)


def open_folder(
    parent: int, name: str, owner: tuple[int, int], label: object, *, create: bool
) -> int | None:
    """The folder `name` below the descriptor `parent`, never through a symbolic link.
    With `create`, a missing folder is made 0700 and handed to `owner`; without it a
    missing folder is None. The caller checks the owner of an existing folder."""
    created = False
    if create:
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
            created = True
        except FileExistsError:
            pass
    try:
        fd = os.open(name, DIR_FLAGS, dir_fd=parent)
    except FileNotFoundError:
        if create:
            raise OwnerError(f"{label} disappeared while it was opened") from None
        return None
    except OSError as exc:
        raise OwnerError(
            f"{label} is not a folder of its own (a symbolic link is refused when "
            f"papaia-ctl runs as root): {exc.strerror}"
        ) from None
    if created:
        try:
            os.fchmod(fd, 0o700)
            os.fchown(fd, *owner)
        except BaseException:
            os.close(fd)
            raise
    return fd


def check_folder(
    fd: int, owners: tuple[int, ...], label: object, *, private: bool = True
) -> None:
    """A folder a root run writes in: owned by one of `owners` and, when `private` (a
    folder that holds what grants rights), not writable by group or others. A folder such
    as `audit/` that the owner's own runs make with the umask of the login need not be
    private: root opens everything in it without a link and checks each file."""
    st = os.fstat(fd)
    if st.st_uid not in owners:
        raise OwnerError(
            f"{label} is owned by uid {st.st_uid}, neither by root nor by the owner of the "
            "configuration directory"
        )
    if private and st.st_mode & _WRITABLE:
        raise OwnerError(f"{label} is writable by group or others (chmod go-w)")


def open_file(
    folder: int,
    name: str,
    flags: int,
    owner: tuple[int, int],
    label: object,
    *,
    exclusive: bool = False,
) -> int:
    """The file `name` in the folder descriptor `folder`, opened with `flags`, never
    through a symbolic link. With O_CREAT a missing file is created 0600 and handed to
    `owner`; without it a missing file raises FileNotFoundError. An existing file must be
    a regular file of `owner` with one link; with `exclusive` it is refused."""
    if flags & os.O_CREAT:
        try:
            fd = os.open(name, flags | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                         dir_fd=folder)
        except FileExistsError:
            if exclusive:
                raise OwnerError(f"{label} exists already") from None
        except OSError as exc:
            raise OwnerError(f"{label} cannot be created: {exc.strerror}") from None
        else:
            try:
                os.fchmod(fd, 0o600)
                os.fchown(fd, *owner)
            except BaseException:
                os.close(fd)
                raise
            return fd
    try:
        fd = os.open(name, (flags & ~os.O_CREAT) | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=folder)
    except FileNotFoundError:
        if flags & os.O_CREAT:
            raise OwnerError(f"{label} disappeared while it was opened") from None
        raise
    except OSError as exc:
        raise OwnerError(
            f"{label} cannot be opened (a symbolic link is refused when papaia-ctl runs as "
            f"root): {exc.strerror}"
        ) from None
    st = os.fstat(fd)
    problem = None
    if not stat.S_ISREG(st.st_mode):
        problem = "is not a regular file"
    elif st.st_nlink != 1:
        problem = f"has {st.st_nlink} links; a root run writes only a file with one link"
    elif st.st_uid != owner[0]:
        problem = (f"is owned by uid {st.st_uid}, not by the owner of the configuration "
                   f"directory (uid {owner[0]})")
    if problem:
        os.close(fd)
        raise OwnerError(f"{label} {problem}")
    return fd
