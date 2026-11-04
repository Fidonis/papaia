# shellcheck shell=bash
# papaia-ctl — finding a Python interpreter that can run tools/lib.
# Sourced by tools/papaia-ctl; not executable on its own.

PYTHON_MIN_VERSION="3.10"

# Prints major.minor.micro of interpreter $1, or nothing when it does not run. Also
# understood by Python 2, which `python` can still be.
_python_version() {
    "$1" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null
}

# Sets PYTHON_BIN to the first interpreter on PATH at PYTHON_MIN_VERSION or newer. macOS
# puts the Command Line Tools' Python 3.9 at `python3` and Homebrew's at `python3.X`,
# so the versioned names are tried as well. Otherwise prints why and returns 1.
find_python() {
    local candidate version too_old=""
    PYTHON_BIN=""
    for candidate in python3 python python3.14 python3.13 python3.12 python3.11 python3.10; do
        # command -v alone isn't enough: on Windows, `python3`/`python` may
        # resolve to the Microsoft Store's inert app-execution-alias stub even
        # when no real interpreter is installed under that name. Only accept a
        # candidate that actually runs.
        command -v "$candidate" >/dev/null 2>&1 || continue
        version="$(_python_version "$candidate")" || continue
        [ -n "$version" ] || continue
        if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info[:2] >= (3, 10) else 1)' \
            >/dev/null 2>&1; then
            # shellcheck disable=SC2034  # consumed by tools/papaia-ctl and the libraries
            PYTHON_BIN="$candidate"
            return 0
        fi
        [ -n "$too_old" ] || too_old="$candidate $version ($(command -v "$candidate"))"
    done
    if [ -n "$too_old" ]; then
        error "papaia-ctl requires Python $PYTHON_MIN_VERSION or newer; found $too_old."
        error "  macOS:         brew install python pyyaml"
        error "  Debian/Ubuntu: sudo apt-get install -y python3 python3-yaml"
        error "Put the newer python3 first on PATH and re-run."
    else
        error "python3 not found on PATH. papaia-ctl requires Python $PYTHON_MIN_VERSION or newer."
    fi
    return 1
}
