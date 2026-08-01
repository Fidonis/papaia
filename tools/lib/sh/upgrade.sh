# shellcheck shell=bash
# papaia-ctl — upgrade command: move an installation to a release.
# Sourced by tools/papaia-ctl; not executable on its own.
# shellcheck disable=SC2154  # globals (colors, CONFIG_DIR, ...) come from the entrypoint

# ─────────────────────────────────────────────────────────────────────────
# The upgrade runs in two phases, split by the checkout:
#
#   phase 1 (this release)  preflight, target resolution, add-on gate,
#                           backup, stop, `git checkout <tag>`
#   phase 2 (target release) migrations, re-render, start
#
# Between them the script re-executes itself from the new tree. That is not
# cosmetic: bash reads the running script lazily, so replacing papaia-ctl
# underneath a live invocation can misparse whatever has not been read yet.
# It is also the correct division of labour -- the migrations, the render
# logic and the setup pass that belong to the target release are the ones
# that must run against the config bundle.
# ─────────────────────────────────────────────────────────────────────────

_UPGRADE_TMPDIR=""
_UPGRADE_WORKTREE=""

_upgrade_cleanup() {
    if [ -n "$_UPGRADE_WORKTREE" ]; then
        git -C "$REPO_ROOT" worktree remove --force "$_UPGRADE_WORKTREE" >/dev/null 2>&1 || true
        _UPGRADE_WORKTREE=""
    fi
    if [ -n "$_UPGRADE_TMPDIR" ]; then
        rm -rf "$_UPGRADE_TMPDIR"
        _UPGRADE_TMPDIR=""
    fi
    return 0
}

# $1 = from version, $2 = to version, $3 = result, rest = key=value details
_upgrade_log() {
    local from="$1" to="$2" result="$3"
    shift 3
    printf '%s upgrade from=%s to=%s result=%s %s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$from" "$to" "$result" "$*" \
        >> "$CONFIG_DIR/upgrade.log" 2>/dev/null || true
    return 0
}

# Same invocation as py_cli, but against a different core tree: the running
# code evaluates a candidate checkout (mirrors `addon check --target-core`).
_py_cli_at() {
    local root="$1"; shift
    PYTHONPATH="$REPO_ROOT/tools${PYTHONPATH:+:$PYTHONPATH}" \
        "$PYTHON_BIN" -m lib.cli --repo-root "$root" --config-dir "$CONFIG_DIR" "$@"
}

# Print the pending migrations of a core tree as indented lines. Returns 1 when
# there are none, so callers can phrase the "nothing to do" case themselves.
# $1 = core tree, $2 = from version, $3 = to version
_upgrade_print_migrations() {
    local root="$1" from="$2" to="$3" found=1
    local marker id version rest
    while IFS=$'\t' read -r marker id version rest; do
        [ "$marker" = "MIGRATION" ] || continue
        found=0
        info "    $id  (ships with $version)"
    done < <(_py_cli_at "$root" upgrade-plan --from="$from" --to="$to" 2>/dev/null | tr -d '\r')
    return "$found"
}

cmd_upgrade() {
    local config_dir="$DEFAULT_CONFIG_DIR" version="" no_backup=0 force=0
    local assume_yes=0 dry_run=0
    local resume_from="" resume_target="" resume_restore_point=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --version=*) version="${1#*=}" ;;
            --no-backup) no_backup=1 ;;
            --force) force=1 ;;
            --dry-run) dry_run=1 ;;
            -y|--yes) assume_yes=1 ;;
            --resume-from=*) resume_from="${1#*=}" ;;
            --resume-target=*) resume_target="${1#*=}" ;;
            --resume-restore-point=*) resume_restore_point="${1#*=}" ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for upgrade: $1"; exit 2 ;;
        esac
        shift
    done
    CONFIG_DIR="$config_dir"
    _require_setup_done

    if [ -n "$resume_from" ]; then
        if [ -z "$resume_target" ]; then
            error "--resume-from requires --resume-target. Both are set by papaia-ctl itself."
            exit 2
        fi
        _upgrade_apply "$resume_from" "$resume_target" "$resume_restore_point" "$force"
        return 0
    fi

    trap _upgrade_cleanup EXIT INT TERM

    # --- preflight --------------------------------------------------------
    if ! git -C "$REPO_ROOT" rev-parse --git-dir >/dev/null 2>&1; then
        error "$REPO_ROOT is not a git checkout."
        error "'upgrade' moves the checkout to a release tag, so it needs one."
        error "Re-clone with 'git clone https://github.com/Fidonis/papaia.git' and re-run"
        error "'papaia-ctl setup --config-dir=$CONFIG_DIR' against your existing config directory."
        exit 2
    fi
    # Only tracked modifications block: git refuses the checkout itself if an
    # untracked file were about to be overwritten, and every file papaia-ctl
    # writes into the checkout (src/**/.env, the generated realm JSON) is
    # gitignored, so a healthy installation is clean here.
    if [ -n "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=no)" ]; then
        error "The checkout has uncommitted changes to tracked files:"
        git -C "$REPO_ROOT" status --short --untracked-files=no >&2
        error "Commit, stash or discard them first — the upgrade has to move the checkout"
        error "to a release tag and would otherwise take your edits with it."
        exit 2
    fi

    info "Fetching release tags..."
    if ! git -C "$REPO_ROOT" fetch --tags --quiet origin 2>/dev/null; then
        warn "Could not reach the remote. Falling back to the tags already in this checkout —"
        warn "a newer release may exist that is not visible here."
    fi

    _UPGRADE_TMPDIR="$(mktemp -d)"
    local tags_file="$_UPGRADE_TMPDIR/tags"
    git -C "$REPO_ROOT" tag --list > "$tags_file"

    # --- resolve target ---------------------------------------------------
    local -a resolve_flags=()
    [ -n "$version" ] && resolve_flags+=(--version="$version")
    local resolved
    # tr -d '\r': on Windows the interpreter emits CRLF and IFS=$'\t' leaves the
    # CR on the last field — a tag name ending in CR matches no ref.
    if ! resolved="$(py_cli upgrade-resolve --tags-file="$tags_file" \
            "${resolve_flags[@]}" | tr -d '\r')"; then
        exit 3
    fi

    local current="" target="" tag="" status=""
    local key value
    while IFS=$'\t' read -r key value; do
        case "$key" in
            CURRENT) current="$value" ;;
            TARGET)  target="$value" ;;
            TAG)     tag="$value" ;;
            STATUS)  status="$value" ;;
        esac
    done <<< "$resolved"

    if [ "$status" = "up-to-date" ]; then
        success "Already at $current — no newer release available."
        return 0
    fi

    info "Upgrade: $current → $target ($tag)"

    # --- add-on gate + migration preview ----------------------------------
    # A worktree of the target tag is the honest way to answer both questions
    # before anything is touched: it carries the target's ADDON_API window and
    # its migration directory.
    local worktree="$_UPGRADE_TMPDIR/target"
    if ! git -C "$REPO_ROOT" worktree add --detach --quiet "$worktree" "$tag" 2>/dev/null; then
        error "Could not check out $tag for inspection. Does the tag exist?"
        exit 3
    fi
    _UPGRADE_WORKTREE="$worktree"

    local -a check_flags=()
    [ "$force" -eq 1 ] && check_flags+=(--force)
    info "Checking active add-ons against $target..."
    if ! _py_cli_at "$worktree" addon-check "${check_flags[@]}"; then
        error "Add-on compatibility check failed against $target. Nothing has been changed."
        error "Update the add-ons first, or re-run with --force to upgrade anyway."
        exit 2
    fi

    info "Migrations to run:"
    if ! _upgrade_print_migrations "$worktree" "$current" "$target"; then
        info "    none"
    fi

    if [ "$dry_run" -eq 1 ]; then
        _upgrade_cleanup
        success "dry run complete — nothing was changed."
        return 0
    fi

    # --- confirm ----------------------------------------------------------
    warn "The upgrade will remove and recreate the containers (volumes are kept),"
    warn "move the checkout to $tag, run the migrations above, re-render the"
    warn "configuration and start the stack again."
    [ "$no_backup" -eq 1 ] && warn "  --no-backup: no restore point is created beforehand."
    if [ "$assume_yes" -eq 0 ]; then
        if ! is_tty; then
            error "Refusing to upgrade without confirmation. Re-run with -y in non-interactive contexts."
            exit 2
        fi
        if ! confirm "Proceed with the upgrade to $target?" "N"; then
            error "Aborted."
            exit 3
        fi
    fi

    # --- backup -----------------------------------------------------------
    local restore_point=""
    if [ "$no_backup" -eq 0 ]; then
        info "Creating a restore point before the upgrade..."
        cmd_backup --config-dir="$CONFIG_DIR"
        restore_point="$LAST_BACKUP_ID"
    fi

    # --- stop + move the checkout -----------------------------------------
    # --clean-up, i.e. `docker compose down`: the containers are REMOVED, not
    # merely stopped, for the same reason _restore_teardown gives in backup.sh.
    # Most core services bind-mount individual *files* out of the config dir
    # (prometheus.yml, librechat.yaml, settings.yml, keycloak.conf, ...), and a
    # stopped container keeps the mount source it was created with — under
    # Docker Desktop a proxy path derived from the file's inode. The render pass
    # further down replaces every one of those files, so starting such a
    # container again fails in the daemon with a missing mount source. Only a
    # recreated container resolves its binds afresh. Volumes are untouched.
    info "Stopping and removing the containers (volumes are kept)..."
    cmd_stop --clean-up --addons --config-dir="$CONFIG_DIR"

    _upgrade_cleanup  # the EXIT trap does not fire across the exec below

    info "Moving the checkout to $tag..."
    if ! git -C "$REPO_ROOT" checkout --detach --quiet "$tag"; then
        error "Could not check out $tag. The stack is stopped and the checkout is unchanged."
        error "Start it again with 'papaia-ctl start --addons'."
        _upgrade_log "$current" "$target" failed "stage=checkout"
        exit 3
    fi

    _upgrade_log "$current" "$target" checkout "restore_point=${restore_point:-none}"

    local -a resume_flags=(
        --config-dir="$CONFIG_DIR"
        --resume-from="$current"
        --resume-target="$target"
    )
    [ -n "$restore_point" ] && resume_flags+=(--resume-restore-point="$restore_point")
    [ "$force" -eq 1 ] && resume_flags+=(--force)
    exec "$REPO_ROOT/tools/papaia-ctl" upgrade "${resume_flags[@]}"
}

# Phase 2 — runs from the target release's checkout.
# $1 = from version, $2 = target version, $3 = restore point (may be empty),
# $4 = force flag
_upgrade_apply() {
    local from="$1" target="$2" restore_point="$3" force="$4"
    local previous_tag="v$from"

    info "Running $target's papaia-ctl from here on."

    local plan_file
    plan_file="$(mktemp)"
    # tr -d '\r': see the note in cmd_upgrade — a CR would end up inside a
    # migration path and make the script unfindable.
    if ! py_cli upgrade-plan --from="$from" --to="$target" | tr -d '\r' > "$plan_file"; then
        rm -f "$plan_file"
        error "Could not determine the pending migrations."
        _upgrade_failed "$from" "$target" "$restore_point" "$previous_tag" \
            "nothing has been migrated yet — the stack is stopped" "stage=plan"
    fi

    local marker id version path kind
    local -a ids=() versions=() paths=() kinds=()
    while IFS=$'\t' read -r marker id version path kind; do
        [ "$marker" = "MIGRATION" ] || continue
        ids+=("$id"); versions+=("$version"); paths+=("$path"); kinds+=("$kind")
    done < "$plan_file"
    rm -f "$plan_file"

    if [ ${#ids[@]} -eq 0 ]; then
        info "No migrations to run."
    else
        info "Running ${#ids[@]} migration(s)..."
        local i
        for i in "${!ids[@]}"; do
            if ! _run_migration "${ids[$i]}" "${versions[$i]}" "${paths[$i]}" "${kinds[$i]}" \
                    "$from" "$target"; then
                error "Migration ${ids[$i]} failed. The upgrade stops here."
                _upgrade_failed "$from" "$target" "$restore_point" "$previous_tag" \
                    "the stack is stopped and $CONFIG_DIR is unchanged apart from the migrations that already ran" \
                    "stage=migration id=${ids[$i]}"
            fi
        done
    fi

    # The setup pass is what makes the bundle match the new release: it renames
    # and drops env keys, adds the keys of new .env.example entries, generates
    # the secrets behind them, re-stamps PAPAIA_VERSION and platform_version,
    # and re-renders every config file and override. --env-only keeps every
    # answered question (hosts, providers, profiles) exactly as it was.
    info "Applying $target's configuration to $CONFIG_DIR..."
    if ! cmd_setup --env-only --config-dir="$CONFIG_DIR"; then
        error "Could not apply $target's configuration."
        _upgrade_failed "$from" "$target" "$restore_point" "$previous_tag" \
            "every migration ran, but the configuration was not re-rendered — the stack is stopped" \
            "stage=render"
    fi

    local -a start_flags=(--addons --config-dir="$CONFIG_DIR")
    [ "$force" = "1" ] && start_flags+=(--force)
    info "Starting the stack..."
    if ! cmd_start "${start_flags[@]}"; then
        error "The stack did not come up on $target."
        _upgrade_failed "$from" "$target" "$restore_point" "$previous_tag" \
            "the upgrade itself is complete — only the start failed, so 'papaia-ctl start --addons' may be all that is missing" \
            "stage=start"
    fi

    _upgrade_log "$from" "$target" ok \
        "migrations=${#ids[@]} restore_point=${restore_point:-none}"
    success "upgrade complete: $from → $target"
    if [ -n "$restore_point" ]; then
        info "Restore point taken before the upgrade: $restore_point"
    fi
}

# Abort the upgrade with the exact commands needed to get back. No automatic
# rollback: a rollback that fails after a migration failed leaves an
# installation nobody can reason about, and the operator may well prefer to fix
# the cause and re-run — the ledger makes that safe.
# $1 from, $2 target, $3 restore point, $4 previous tag, $5 one-line description
# of the state the installation is in, rest = log details
_upgrade_failed() {
    local from="$1" target="$2" restore_point="$3" previous_tag="$4" situation="$5"
    shift 5
    _upgrade_log "$from" "$target" failed "$*"
    error ""
    error "The checkout is on v$target and $situation."
    error ""
    error "To go back to $from:"
    error "    git -C $REPO_ROOT checkout $previous_tag"
    if [ -n "$restore_point" ]; then
        error "    papaia-ctl restore --restore-point=$restore_point --config-dir=$CONFIG_DIR"
    else
        error "    papaia-ctl start --addons --config-dir=$CONFIG_DIR"
        error "  (no restore point was created — the upgrade ran with --no-backup)"
    fi
    error ""
    error "To retry after fixing the cause, run 'papaia-ctl upgrade --version=$target'"
    error "again: migrations that already succeeded are recorded and will be skipped."
    exit 3
}

# Run one migration script in a subshell. $1 id, $2 version, $3 path, $4 kind,
# $5 from version, $6 target version.
_run_migration() {
    local id="$1" version="$2" path="$3" kind="$4" from="$5" to="$6"
    local started=$SECONDS rc=0
    info "  $id"
    (
        cd "$REPO_ROOT" || exit 1
        # PYTHONPATH lets .py migrations import lib.* — YAML/.env manipulation
        # stays on the Python side of the split, exactly as in the CLI.
        export PAPAIA_CONFIG_DIR="$CONFIG_DIR" \
               PAPAIA_REPO_ROOT="$REPO_ROOT" \
               PAPAIA_FROM_VERSION="$from" \
               PAPAIA_TO_VERSION="$to" \
               PAPAIA_MIGRATION_VERSION="$version" \
               PYTHONPATH="$REPO_ROOT/tools${PYTHONPATH:+:$PYTHONPATH}"
        case "$kind" in
            sh) bash "$path" ;;
            py) "$PYTHON_BIN" "$path" ;;
            *)  echo "unknown migration kind: $kind" >&2; exit 1 ;;
        esac
    ) || rc=$?
    if [ "$rc" -ne 0 ]; then
        return "$rc"
    fi
    py_cli upgrade-record --migration-id="$id" --duration="$((SECONDS - started))"
}
