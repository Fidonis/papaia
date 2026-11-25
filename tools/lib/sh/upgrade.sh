# shellcheck shell=bash
# papaia-ctl — upgrade command: move an installation to a release.
# Sourced by tools/papaia-ctl; not executable on its own.
# shellcheck disable=SC2154  # globals (colors, CONFIG_DIR, ...) come from the entrypoint

# ─────────────────────────────────────────────────────────────────────────
# The upgrade runs in two phases, split by the checkout:
#
#   phase 1 (this release)  stage 0 (target resolution, add-on and suite-matrix
#                           check, stage plan, image check, operator key check),
#                           stage 1 (restore point R0, write lock), stop,
#                           `git checkout <tag>`
#   phase 2 (target release) stage 2 (migrations, re-render, start), module
#                           stages 3-7 (`addon upgrade` per module), stage 8
#                           (write lock off, stage durations)
#
# The stage state and the write lock are kept by lib/upgrade_stages.py.
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
# The rollback key stage 0 made, until stage 1 began the run with it (lib/rollback_key.py).
_UPGRADE_NEW_KEY=""
# The stage a failure is recorded against.
_UPGRADE_STAGE="core"

_upgrade_cleanup() {
    if [ -n "$_UPGRADE_WORKTREE" ]; then
        git -C "$REPO_ROOT" worktree remove --force "$_UPGRADE_WORKTREE" >/dev/null 2>&1 || true
        _UPGRADE_WORKTREE=""
    fi
    if [ -n "$_UPGRADE_TMPDIR" ]; then
        rm -rf "$_UPGRADE_TMPDIR"
        _UPGRADE_TMPDIR=""
    fi
    # A run that stopped before stage 1 began needs no way back.
    if [ -n "$_UPGRADE_NEW_KEY" ]; then
        py_cli rollback-key discard --upgrade-id="$_UPGRADE_NEW_KEY" >/dev/null 2>&1 || true
        _UPGRADE_NEW_KEY=""
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

# One correlation id for every audit row of this run (lib/backup_crypt.py reads it).
_upgrade_correlation() {
    if [ -z "${PAPAIA_CORRELATION_ID:-}" ]; then
        PAPAIA_CORRELATION_ID="$(py_cli new-correlation-id | tr -d '\r')" || exit 3
    fi
    export PAPAIA_CORRELATION_ID
}

# Stage 0 without a rollback key: the operator's backup key must open a check block
# encrypted to the backup recipients (lib/upgrade_stages.py). The key is read by the
# Python side and never written anywhere. $1 = --identity value, may be empty.
_upgrade_check_key() {
    local -a flags=()
    [ -n "$1" ] && flags+=(--identity="$1")
    py_cli upgrade-stage identity-check ${flags[@]+"${flags[@]}"} || return 2
}

# The add-on check of a core tree as JSON, for the stage plan. A refusal (exit 2) still
# writes its verdicts; anything else, or no output at all, means the check itself failed,
# and its error output is shown instead of planning on an empty result.
# $1 = core tree, $2 = output file, $3 = target version
_upgrade_addon_check() {
    local root="$1" out="$2" target="$3" rc=0 line
    _py_cli_at "$root" addon-check --json > "$out" 2> "$out.err" || rc=$?
    if { [ "$rc" -eq 0 ] || [ "$rc" -eq 2 ]; } && [ -s "$out" ]; then
        rm -f "$out.err"
        return 0
    fi
    error "The add-on check against $target gave no result (exit $rc):"
    while IFS= read -r line; do
        error "    $line"
    done < "$out.err"
    rm -f "$out.err"
    return 1
}

cmd_upgrade() {
    local config_dir="$DEFAULT_CONFIG_DIR" version="" force=0
    local assume_yes=0 dry_run=0 insecure_images=0
    local identity="" stage_sel="" resume=0 release_lock=0 finalize=0 no_rollback_key=0
    local -a addon_paths=()
    local resume_from="" resume_target="" resume_restore_point=""
    local resume_anchor="" resume_correlation="" resume_stages="" resume_started=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --version=*) version="${1#*=}" ;;
            --no-backup)
                error "--no-backup is no longer accepted: the upgrade always takes restore point"
                error "R0 first, so that a failed stage can go back to it. Nothing has been changed."
                exit 2
                ;;
            --identity=*) identity="${1#*=}" ;;
            --stage=*) stage_sel="${1#*=}" ;;
            --addon-path=*) addon_paths+=(--addon-path="${1#*=}") ;;
            --resume) resume=1 ;;
            --release-lock) release_lock=1 ;;
            --finalize) finalize=1 ;;
            --no-rollback-key) no_rollback_key=1 ;;
            --force) force=1 ;;
            --dry-run) dry_run=1 ;;
            --insecure-images) insecure_images=1 ;;
            -y|--yes) assume_yes=1 ;;
            --resume-from=*) resume_from="${1#*=}" ;;
            --resume-target=*) resume_target="${1#*=}" ;;
            --resume-restore-point=*) resume_restore_point="${1#*=}" ;;
            --resume-anchor=*) resume_anchor="${1#*=}" ;;
            --resume-correlation-id=*) resume_correlation="${1#*=}" ;;
            --resume-stages=*) resume_stages="${1#*=}" ;;
            --resume-started=*) resume_started="${1#*=}" ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for upgrade: $1"; exit 2 ;;
        esac
        shift
    done
    CONFIG_DIR="$config_dir"
    _require_setup_done
    local distributed=0 mode
    mode="$(_topology_mode)" || exit 3
    [ "$mode" = "distributed" ] && distributed=1
    # The upgrade's own backup, stop and start are not held up by the lock it takes (and
    # a retry by the lock an earlier attempt left).
    [ "$distributed" -eq 1 ] && UPGRADE_IN_PROGRESS=1
    # The rollback key goes with a restore point of this host's backup; a distributed
    # installation checks the operator key in stage 0 instead.
    [ "$distributed" -eq 1 ] && no_rollback_key=1

    if [ "$release_lock" -eq 1 ]; then
        if [ "$assume_yes" -eq 0 ]; then
            if ! is_tty; then
                error "Refusing to release the write lock without confirmation. Re-run with -y."
                exit 2
            fi
            if ! confirm "Release the write lock of the unfinished upgrade?" "N"; then
                error "Aborted."
                exit 3
            fi
        fi
        _upgrade_correlation
        py_cli upgrade-stage release-lock || exit 2
        return 0
    fi

    if [ "$finalize" -eq 1 ]; then
        if [ "$assume_yes" -eq 0 ]; then
            if ! is_tty; then
                error "Refusing to delete the rollback key without confirmation. Re-run with -y."
                exit 2
            fi
            if ! confirm "Delete the rollback key? Going back then needs the operator key." "N"; then
                error "Aborted."
                exit 3
            fi
        fi
        _upgrade_correlation
        py_cli upgrade-stage finalize || exit 2
        return 0
    fi

    if [ "$resume" -eq 1 ]; then
        _upgrade_correlation
        local resumed key value r_from="" r_to="" r_point="" r_key=0
        resumed="$(py_cli upgrade-stage resume-check | tr -d '\r')" || exit 2
        while IFS=$'\t' read -r key value; do
            case "$key" in
                FROM) r_from="$value" ;;
                TO) r_to="$value" ;;
                RESTORE_POINT) r_point="$value" ;;
                ROLLBACK_KEY) r_key="$value" ;;
            esac
        done <<< "$resumed"
        # The run's rollback key is the way back; without it the operator key is checked.
        if [ "$r_key" != "1" ] || [ -n "$identity" ]; then
            _upgrade_check_key "$identity" || exit 2
        fi
        _upgrade_module_stages "$r_from" "$r_to" "$r_point" "$stage_sel" "$force" \
            "$insecure_images"
        return 0
    fi

    if [ -n "$resume_from" ]; then
        if [ -z "$resume_target" ]; then
            error "--resume-from requires --resume-target. Both are set by papaia-ctl itself."
            exit 2
        fi
        # Handed over by the first phase, never stored: the second phase checks the
        # images against the release key of the core that was installed, and audits
        # under the same correlation id (lib/images.py validates both).
        IMAGES_ANCHOR="$resume_anchor"
        IMAGES_CORRELATION_ID="$resume_correlation"
        [ -n "$resume_correlation" ] && PAPAIA_CORRELATION_ID="$resume_correlation"
        _upgrade_correlation
        if [ -z "$resume_anchor" ] && [ "$insecure_images" -eq 0 ] \
                && [ -z "${TEST_TRUST_ANCHOR:-}" ]; then
            _upgrade_bootstrap_notice "$resume_target"
        fi
        if ! [[ "$resume_started" =~ ^[0-9]{1,12}$ ]]; then
            resume_started="$(date +%s)"
        fi
        _upgrade_adopt "$resume_from" "$resume_target" "$resume_restore_point" "$force"
        _upgrade_apply "$resume_from" "$resume_target" "$resume_restore_point" "$force" \
            "$distributed" "$insecure_images" "$resume_stages" "$resume_started"
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
            ${resolve_flags[@]+"${resolve_flags[@]}"} | tr -d '\r')"; then
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

    # An unfinished run to the same target keeps its restore point; one to another target
    # has to be finished or abandoned first.
    local kept_point
    kept_point="$(py_cli upgrade-stage restore-point --target="$target" | tr -d '\r')" || exit 2

    # --- trust anchor -------------------------------------------------------
    # The release key of the installed core vouches for the target; the target's own
    # key only counts when the installed one signed its rotation (lib/images.py).
    # With --test-trust-anchor (a pre-release core, this command only) the target's bill of
    # materials of scope test is checked against that key instead (lib/prerelease_anchor.py).
    if [ -n "${TEST_TRUST_ANCHOR:-}" ]; then
        IMAGES_ANCHOR=""
    elif IMAGES_ANCHOR="$(py_cli image-trust-anchor)"; then
        :
    elif [ "$insecure_images" -eq 1 ]; then
        IMAGES_ANCHOR=""
        warn "This installation pins no release key; --insecure-images skips the image check."
    else
        error "This installation pins no release key ($REPO_ROOT/compat/release-key.pub),"
        error "so the images of $target cannot be checked. Nothing has been changed."
        error "Re-run with --insecure-images to upgrade without the image check."
        exit 2
    fi
    IMAGES_CORRELATION_ID="$(py_cli new-correlation-id)"
    PAPAIA_CORRELATION_ID="$IMAGES_CORRELATION_ID"
    export PAPAIA_CORRELATION_ID
    # Rollback keys of earlier runs whose window is over go now.
    py_cli rollback-key sweep || true
    # A retry continues the run it keeps, with that run's rollback key or without one: a run
    # begun with --no-rollback-key needs the operator key on every retry as well.
    local kept_key=0
    if [ -n "$kept_point" ]; then
        local kept_out
        kept_out="$(py_cli upgrade-stage kept-key --target="$target" | tr -d '\r')" || exit 2
        [ "$kept_out" = "ROLLBACK_KEY"$'\t'"1" ] && kept_key=1
    fi
    local needs_identity=0
    if [ "$no_rollback_key" -eq 1 ] || { [ -n "$kept_point" ] && [ "$kept_key" -eq 0 ]; }; then
        needs_identity=1
    fi

    # The commit the tag names now: what is checked below is what is checked out later.
    local commit
    if ! commit="$(git -C "$REPO_ROOT" rev-parse --verify --quiet "$tag^{commit}")" ||
            [ -z "$commit" ]; then
        error "Could not resolve $tag. Does the tag exist?"
        exit 3
    fi

    # --- add-on gate + migration preview ----------------------------------
    # A worktree of the target tag is the honest way to answer both questions
    # before anything is touched: it carries the target's ADDON_API window and
    # its migration directory.
    local worktree="$_UPGRADE_TMPDIR/target"
    if ! git -C "$REPO_ROOT" worktree add --detach --quiet "$worktree" "$commit" 2>/dev/null; then
        error "Could not check out $tag for inspection. Does the tag exist?"
        exit 3
    fi
    _UPGRADE_WORKTREE="$worktree"

    # Stage 0: the stage plan. Each module either gets the checkout named with
    # --addon-path, stays (the target still accepts it), or stops the upgrade here;
    # with --force such a module is stopped and blocked instead.
    local check_file="$_UPGRADE_TMPDIR/addon-check.json" steps_file="$_UPGRADE_TMPDIR/steps.json"
    if ! _upgrade_addon_check "$worktree" "$check_file" "$target"; then
        error "Nothing has been changed."
        exit 2
    fi
    local -a plan_flags=(--check-file="$check_file" --target="$target" \
        --target-core="$worktree" --out="$steps_file")
    [ "$force" -eq 1 ] && plan_flags+=(--force)
    [ -n "$stage_sel" ] && plan_flags+=(--stage="$stage_sel")
    local plan_text
    if ! plan_text="$(py_cli upgrade-stage plan ${plan_flags[@]+"${plan_flags[@]}"} \
            ${addon_paths[@]+"${addon_paths[@]}"} | tr -d '\r')"; then
        error "Nothing has been changed."
        exit 2
    fi

    local -a check_flags=()
    [ "$force" -eq 1 ] && check_flags+=(--force)
    info "Checking active add-ons against $target..."
    if ! _py_cli_at "$worktree" addon-check ${check_flags[@]+"${check_flags[@]}"}; then
        error "Add-on compatibility check failed against $target. Nothing has been changed."
        error "Update the add-ons first, or re-run with --force to upgrade anyway."
        exit 2
    fi

    # Stage 0: every image of the target and of the active add-ons against the target's
    # bill of materials, that bill against the installed release key, before anything is
    # backed up, stopped or moved. The second phase's start checks the ones it runs again
    # after the render.
    local verified=0
    _addon_image_flags
    ( _verify_images upgrade "$worktree" "" 1 "$insecure_images" \
        ${ADDON_IMAGE_FLAGS[@]+"${ADDON_IMAGE_FLAGS[@]}"} ) || verified=$?
    _addon_image_files_remove
    if [ "$verified" -ne 0 ]; then
        error "Nothing has been changed."
        exit 2
    fi

    info "Migrations to run:"
    if ! _upgrade_print_migrations "$worktree" "$current" "$target"; then
        info "    none"
    fi

    if [ "$distributed" -eq 1 ]; then
        # Stop the world: every node moves to the same release in one run, so every node
        # has to answer before anything is touched.
        info "Checking that every node answers..."
        py_cli cluster-upgrade-check || exit 3
        # Here, not when the migrations run: by then the stack is down and the checkout moved.
        info "Checking where the migrations run..."
        _py_cli_at "$worktree" upgrade-plan --from="$current" --to="$target" --check-markers \
            >/dev/null || exit 3
    fi

    info "Upgrade stages:"
    local line
    while IFS= read -r line; do
        [ -n "$line" ] && info "    $line"
    done <<< "$plan_text"

    if [ "$dry_run" -eq 1 ]; then
        if [ -n "$identity" ]; then
            _upgrade_check_key "$identity" || exit 2
        fi
        if [ "$needs_identity" -eq 0 ] && [ -n "$kept_point" ]; then
            info "The unfinished run keeps its rollback key: 'papaia-ctl rollback' needs no"
            info "operator key (--identity) until the window after the upgrade ends."
        elif [ "$needs_identity" -eq 0 ]; then
            info "Stage 0 makes a one-off rollback key for this upgrade and R0 is encrypted to"
            info "it as well: 'papaia-ctl rollback' then needs no operator key (--identity)"
            info "until the window after the upgrade ends."
        elif [ -z "$identity" ]; then
            info "Stage 0 needs the backup key of a recipient: there is no rollback key for"
            info "this upgrade, so pass --identity=FILE (or --identity=- for standard input)."
        fi
        _upgrade_cleanup
        success "dry run complete — nothing was changed."
        return 0
    fi

    # Stage 0, last check: without a way back nothing is started. Without a rollback key
    # (none asked for, or the kept run has none) the operator key must open a check block;
    # a key given anyway is checked as well.
    if [ "$needs_identity" -eq 1 ] || [ -n "$identity" ]; then
        _upgrade_check_key "$identity" || exit 2
    fi
    local upgrade_id=""
    if [ "$no_rollback_key" -eq 0 ] && [ -z "$kept_point" ]; then
        if _UPGRADE_NEW_KEY="$(py_cli rollback-key create | tr -d '\r')" &&
                [ -n "$_UPGRADE_NEW_KEY" ]; then
            upgrade_id="$_UPGRADE_NEW_KEY"
            info "Stage 0: a rollback key for this upgrade is kept on this host only."
        elif [ -n "$identity" ]; then
            _UPGRADE_NEW_KEY=""
            warn "No rollback key could be made; the way back needs the backup key checked above."
        else
            _UPGRADE_NEW_KEY=""
            error "No rollback key could be made for this upgrade."
            _upgrade_check_key "" || exit 2
        fi
    fi

    # --- confirm ----------------------------------------------------------
    warn "The upgrade will remove and recreate the containers (volumes are kept),"
    warn "move the checkout to $tag, run the migrations above, re-render the"
    warn "configuration and start the stack again."
    warn "From the restore point on, every module accepts reads only until the upgrade ends."
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

    # --- stage 1: restore point R0 and write lock --------------------------
    local restore_point=""
    if [ -n "$kept_point" ]; then
        restore_point="$kept_point"
        info "Restore point $restore_point of the unfinished upgrade to $target is kept as R0."
    else
        info "Stage 1: creating restore point R0..."
        local -a backup_flags=(--config-dir="$CONFIG_DIR")
        [ -n "$upgrade_id" ] && backup_flags+=(--rollback-key="$upgrade_id")
        cmd_backup ${backup_flags[@]+"${backup_flags[@]}"}
        restore_point="$LAST_BACKUP_ID"
        if [ -z "$restore_point" ]; then
            error "No restore point was created. Nothing has been changed."
            exit 3
        fi
    fi
    py_cli upgrade-stage begin --from="$current" --to="$target" \
        --restore-point="$restore_point" --steps-file="$steps_file" \
        ${upgrade_id:+--upgrade-id="$upgrade_id"} || exit 3
    _UPGRADE_NEW_KEY=""
    info "Write lock on: every module accepts reads only until the upgrade ends."
    local stage_started
    stage_started="$(date +%s)"

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

    # Modules the target does not accept (--force): stopped above, kept out from here on.
    local blocked
    blocked="$(py_cli upgrade-stage block | tr -d '\r')" || exit 3
    while IFS= read -r line; do
        [ -n "$line" ] && warn "$line is stopped and blocked until a version the target accepts is installed."
    done <<< "$blocked"

    # --- lock ---------------------------------------------------------------
    # From the moment the releases can differ until the upgrade has finished, a distributed
    # installation accepts nothing but the upgrade itself and the way back (restore).
    if [ "$distributed" -eq 1 ]; then
        py_cli cluster-lock --set --from="$current" --to="$target" \
            ${restore_point:+--restore-point="$restore_point"}
    fi

    _upgrade_cleanup  # the EXIT trap does not fire across the exec below

    info "Moving the checkout to $tag..."
    if ! git -C "$REPO_ROOT" checkout --detach --quiet "$commit"; then
        # Nothing moved: no reason to keep the installation locked.
        [ "$distributed" -eq 1 ] && py_cli cluster-lock --clear
        py_cli upgrade-stage record --stage=core --result=failed >/dev/null 2>&1 || true
        error "Could not check out $tag. The stack is stopped and the checkout is unchanged."
        error "Start it again with 'papaia-ctl start --addons', then end the write lock with"
        error "'papaia-ctl upgrade --release-lock -y'."
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
    [ -n "$stage_sel" ] && resume_flags+=(--resume-stages="$stage_sel")
    resume_flags+=(--resume-started="$stage_started")
    [ "$force" -eq 1 ] && resume_flags+=(--force)
    # This command's own second phase; the flag, the anchor and the correlation id are
    # never written anywhere.
    [ "$insecure_images" -eq 1 ] && resume_flags+=(--insecure-images)
    [ -n "$IMAGES_ANCHOR" ] && resume_flags+=(--resume-anchor="$IMAGES_ANCHOR")
    # The target's papaia-ctl takes it out again and refuses it unless it is a pre-release.
    [ -n "${TEST_TRUST_ANCHOR:-}" ] && resume_flags+=(--test-trust-anchor="${TEST_TRUST_ANCHOR:-}")
    resume_flags+=(--resume-correlation-id="$IMAGES_CORRELATION_ID")
    # Hand off through the interpreter, not by executing the path: the git
    # checkout just above rewrote tools/papaia-ctl from the target tree, and it
    # is not guaranteed to carry the execute bit (nor is the checkout guaranteed
    # to sit on an exec-permitting mount). This mirrors how the manager and every
    # migration invoke the script.
    exec "${BASH:-bash}" "$REPO_ROOT/tools/papaia-ctl" upgrade ${resume_flags[@]+"${resume_flags[@]}"}
}

# Phase 2, before the core stage: a first phase of this release began the run (stage
# state, R0, write lock). The first upgrade INTO this release runs the first phase of the
# installed one, which knows no stages: it took a restore point (unless it ran with
# --no-backup), stopped the stack and moved the checkout, but kept no state, took no write
# lock and checked no backup key. Take the run over here with the restore point it handed
# on; without one, stop before anything is migrated.
# $1 = from version, $2 = target version, $3 = restore point (may be empty), $4 = force flag
_upgrade_adopt() {
    local from="$1" target="$2" restore_point="$3" force="$4" kept
    if ! kept="$(py_cli upgrade-stage restore-point --target="$target" | tr -d '\r')"; then
        _upgrade_adopt_refused "$from" "$target" "another upgrade is unfinished"
    fi
    [ -n "$kept" ] && return 0
    if [ -z "$restore_point" ]; then
        error "The release you upgraded from took no restore point (it ran with --no-backup),"
        error "and $target runs its stages only with a restore point R0 to go back to."
        _upgrade_adopt_refused "$from" "$target" "no restore point"
    fi
    warn "The installed release ran the first phase of this upgrade: restore point"
    warn "$restore_point was taken, but there was no key check and no write lock before the"
    warn "checkout moved. $target takes the run over with R0 = $restore_point."
    local tmpdir check_file steps_file
    tmpdir="$(mktemp -d)"
    check_file="$tmpdir/addon-check.json"
    steps_file="$tmpdir/steps.json"
    # The checkout already is the target: its add-on check and suite matrix decide. No
    # module has a new checkout yet; each stays, or is blocked with --force.
    if ! _upgrade_addon_check "$REPO_ROOT" "$check_file" "$target"; then
        rm -rf "$tmpdir"
        _upgrade_adopt_refused "$from" "$target" "add-on check failed"
    fi
    local -a plan_flags=(--check-file="$check_file" --target="$target" \
        --target-core="$REPO_ROOT" --out="$steps_file")
    [ "$force" = "1" ] && plan_flags+=(--force)
    local plan_text line
    if ! plan_text="$(py_cli upgrade-stage plan ${plan_flags[@]+"${plan_flags[@]}"} | tr -d '\r')"; then
        rm -rf "$tmpdir"
        _upgrade_adopt_refused "$from" "$target" "stage plan refused"
    fi
    if ! py_cli upgrade-stage begin --from="$from" --to="$target" \
            --restore-point="$restore_point" --steps-file="$steps_file"; then
        rm -rf "$tmpdir"
        _upgrade_adopt_refused "$from" "$target" "stage state not written"
    fi
    rm -rf "$tmpdir"
    info "Write lock on: every module accepts reads only until the upgrade ends."
    info "Upgrade stages:"
    while IFS= read -r line; do
        [ -n "$line" ] && info "    $line"
    done <<< "$plan_text"
    local blocked
    blocked="$(py_cli upgrade-stage block | tr -d '\r')" || exit 3
    while IFS= read -r line; do
        [ -n "$line" ] && warn "$line is stopped and blocked until a version the target accepts is installed."
    done <<< "$blocked"
    return 0
}

# The run could not be taken over: nothing has been migrated and the configuration is
# still the one of $1, so the way back is the checkout and a start.
# $1 = from version, $2 = target version, $3 = reason for the log
_upgrade_adopt_refused() {
    local from="$1" target="$2"
    _upgrade_log "$from" "$target" failed "stage=handover reason=${3// /-}"
    error "Nothing has been migrated; the stack is stopped and $CONFIG_DIR is still at $from."
    error "To go back to $from:"
    error "    git -C $REPO_ROOT checkout v$from"
    error "    papaia-ctl start --addons --config-dir=$CONFIG_DIR"
    if [ "${UPGRADE_IN_PROGRESS:-0}" = "1" ]; then
        error "    papaia-ctl start --addons --unlock --config-dir=$CONFIG_DIR  (distributed)"
    fi
    error "Then run 'papaia-ctl upgrade --version=$target' again: from $from on the upgrade"
    error "is staged, takes restore point R0 itself and checks the backup key first."
    exit 3
}

# The first upgrade from a core that pinned no release key: its first phase handed no
# anchor over, so the images of the target are checked against the target's own key.
# Name that key so the operator can compare it with the fingerprint published out of
# band (docs/compatibility.md). $1 = target version.
_upgrade_bootstrap_notice() {
    local trusted
    trusted="$(py_cli image-trust-anchor 2>/dev/null)" || return 0
    warn "The installed release pinned no release key, so $1 is checked against its own"
    warn "key $trusted. Compare this fingerprint with the one published for the release,"
    warn "obtained out of band, before you rely on the check."
}

# Phase 2 — runs from the target release's checkout.
# $1 = from version, $2 = target version, $3 = restore point (may be empty),
# $4 = force flag, $5 = 1 for a distributed installation, $6 = 1 for --insecure-images,
# $7 = stage selection (may be empty), $8 = epoch the stack was stopped at
_upgrade_apply() {
    local from="$1" target="$2" restore_point="$3" force="$4" distributed="${5:-0}"
    local insecure_images="${6:-0}" selection="${7:-}" stopped_at="${8:-$(date +%s)}"
    local previous_tag="v$from"
    _UPGRADE_STAGE="core"

    info "Running $target's papaia-ctl from here on."

    if [ "$distributed" -eq 1 ]; then
        _upgrade_apply_distributed "$from" "$target" "$restore_point" "$force" "$insecure_images"
        _upgrade_core_done "$stopped_at"
        _upgrade_module_stages "$from" "$target" "$restore_point" "$selection" "$force" \
            "$insecure_images"
        return 0
    fi

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
    [ "$insecure_images" -eq 1 ] && start_flags+=(--insecure-images)
    info "Starting the stack..."
    # In a subshell: a start that ends with `exit` (a refused image check among others)
    # still reaches the failure report below.
    if ! ( cmd_start ${start_flags[@]+"${start_flags[@]}"} ); then
        error "The stack did not come up on $target."
        _upgrade_failed "$from" "$target" "$restore_point" "$previous_tag" \
            "the upgrade itself is complete — only the start failed, so 'papaia-ctl start --addons' may be all that is missing" \
            "stage=start"
    fi

    _upgrade_log "$from" "$target" ok \
        "migrations=${#ids[@]} restore_point=${restore_point:-none}"
    _upgrade_core_done "$stopped_at"
    success "core and manager at $target (stage 2)"
    _upgrade_module_stages "$from" "$target" "$restore_point" "$selection" "$force" \
        "$insecure_images"
}

# Stage 2 done. $1 = epoch the stack was stopped at: the stage's downtime.
_upgrade_core_done() {
    local seconds=$(( $(date +%s) - $1 ))
    [ "$seconds" -lt 0 ] && seconds=0
    py_cli upgrade-stage record --stage=core --result=ok --seconds="$seconds" || exit 3
}

# Stages 3-8 of a run in progress: the module stages that are due (or the ones named in
# $4, in that order), then the finish stage, which ends the write lock.
# $1 from, $2 target, $3 restore point, $4 stage selection (may be empty), $5 force flag,
# $6 1 for --insecure-images
_upgrade_module_stages() {
    local from="$1" target="$2" restore_point="$3" selection="$4" force="${5:-0}"
    local insecure_images="${6:-0}"
    local -a sel=()
    [ -n "$selection" ] && sel+=(--stage="$selection")
    local steps
    steps="$(py_cli upgrade-stage steps ${sel[@]+"${sel[@]}"} | tr -d '\r')" || exit 2
    local tag stage addon action path started finish=0
    while IFS=$'\t' read -r -u 3 tag stage addon action path; do
        [ "$tag" = "STAGE" ] || continue
        if [ "$stage" = "finish" ]; then
            finish=1
            continue
        fi
        _UPGRADE_STAGE="$stage"
        started=$SECONDS
        case "$action" in
            upgrade)
                info "Stage $stage: upgrading $addon from $path..."
                local -a flags=("$addon" --path="$path" --no-backup -y --config-dir="$CONFIG_DIR")
                [ "$force" = "1" ] && flags+=(--force)
                [ "$insecure_images" = "1" ] && flags+=(--insecure-images)
                # The restore point R0 covers the module; its own migrations run when the
                # new version starts. In a subshell, so a refusal that exits still lands here.
                if ! ( cmd_addon_upgrade ${flags[@]+"${flags[@]}"} ); then
                    error "Stage $stage: the upgrade of $addon did not complete."
                    _upgrade_failed "$from" "$target" "$restore_point" "v$from" \
                        "$addon did not complete its upgrade" "stage=$stage addon=$addon"
                fi
                py_cli upgrade-stage record --stage="$stage" --result=ok \
                    --seconds="$((SECONDS - started))" || exit 3
                ;;
            keep)
                info "Stage $stage: $addon stays at its version."
                py_cli upgrade-stage record --stage="$stage" --result=kept --seconds=0 || exit 3
                ;;
            block)
                warn "Stage $stage: $addon is blocked (stopped, its data untouched)."
                py_cli upgrade-stage record --stage="$stage" --result=blocked --seconds=0 || exit 3
                ;;
            *)
                py_cli upgrade-stage record --stage="$stage" --result=skipped --seconds=0 || exit 3
                ;;
        esac
    done 3<<< "$steps"
    if [ "$finish" -eq 0 ]; then
        warn "The write lock stays on until the remaining stages ran:"
        warn "    papaia-ctl upgrade --resume [--stage=NAME[,NAME]]"
        warn "  (with --identity=FILE when the upgrade has no rollback key)"
        return 0
    fi
    _UPGRADE_STAGE="finish"
    py_cli upgrade-stage finish || exit 3
    success "upgrade complete: $from → $target; the write lock is off."
    info "Restore point taken before the upgrade: $restore_point"
}

# Phase 2 of a distributed installation: every node gets the target release, the
# migrations run where their data lives, then the configuration is re-rendered and the
# installation started in order. The lock is released at the very end.
_upgrade_apply_distributed() {
    local from="$1" target="$2" restore_point="$3" force="$4" insecure_images="${5:-0}"
    local previous_tag="v$from"
    UPGRADE_IN_PROGRESS=1
    info "Installing $target on every node and running the migrations..."
    if ! py_cli cluster-migrate --from="$from" --to="$target"; then
        _upgrade_failed "$from" "$target" "$restore_point" "$previous_tag" \
            "the installation is stopped on every node" "stage=migration"
    fi
    info "Applying $target's configuration to $CONFIG_DIR..."
    if ! cmd_setup --env-only --config-dir="$CONFIG_DIR"; then
        _upgrade_failed "$from" "$target" "$restore_point" "$previous_tag" \
            "every migration ran, but the configuration was not re-rendered — every node is stopped" \
            "stage=render"
    fi
    local -a start_flags=(--addons --config-dir="$CONFIG_DIR")
    [ "$force" = "1" ] && start_flags+=(--force)
    [ "$insecure_images" -eq 1 ] && start_flags+=(--insecure-images)
    info "Starting every node..."
    if ! ( cmd_start ${start_flags[@]+"${start_flags[@]}"} ); then
        # Every node runs $target now; only the start is missing, so nothing to lock.
        py_cli cluster-lock --clear
        UPGRADE_IN_PROGRESS=0
        _upgrade_failed "$from" "$target" "$restore_point" "$previous_tag" \
            "the upgrade itself is complete — only the start failed, so 'papaia-ctl start --addons' may be all that is missing" \
            "stage=start"
    fi
    py_cli cluster-lock --clear
    UPGRADE_IN_PROGRESS=0
    _upgrade_log "$from" "$target" ok "restore_point=${restore_point:-none} distributed=1"
    success "core and manager at $target on every node (stage 2)"
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
    py_cli upgrade-stage record --stage="${_UPGRADE_STAGE:-core}" --result=failed \
        >/dev/null 2>&1 || true
    error ""
    error "The checkout is on v$target and $situation."
    error "The write lock stays on: every module accepts reads only, so going back loses no data."
    error ""
    if [ -n "$restore_point" ] && [ "${UPGRADE_IN_PROGRESS:-0}" != "1" ]; then
        error "To go back to $from in one command:"
        error "    papaia-ctl rollback -y --config-dir=$CONFIG_DIR"
        error "or step by step."
    fi
    error "To go back to $from:"
    error "    git -C $REPO_ROOT checkout $previous_tag"
    if [ -n "$restore_point" ]; then
        error "    papaia-ctl restore --restore-point=$restore_point --config-dir=$CONFIG_DIR"
        error "    papaia-ctl upgrade --release-lock -y --config-dir=$CONFIG_DIR"
    elif [ "${UPGRADE_IN_PROGRESS:-0}" = "1" ]; then
        error "    papaia-ctl start --addons --unlock --config-dir=$CONFIG_DIR"
        error "  (no restore point was created — the upgrade ran with --no-backup; --unlock"
        error "  releases the upgrade lock and puts $from back on every node)"
    else
        error "    papaia-ctl start --addons --config-dir=$CONFIG_DIR"
        error "  (no restore point was created — the upgrade ran with --no-backup)"
    fi
    if [ "${UPGRADE_IN_PROGRESS:-0}" = "1" ]; then
        # The other nodes: each one is put back on $from by the restore above, which
        # installs the controller's release on any node that runs another one.
        local node
        while IFS= read -r node; do
            node="${node%$'\r'}"
            [ -z "$node" ] && continue
            error "  node $node: gets $from again with the restore, or on its own with"
            error "    papaia-ctl node sync $node --checkout --config-dir=$CONFIG_DIR"
        done < <(py_cli node-list --json 2>/dev/null \
            | "$PYTHON_BIN" -c 'import json,sys; [print(r["name"]) for r in json.load(sys.stdin) if not r["controller"]]' 2>/dev/null || true)
        error "  The upgrade lock stays until 'upgrade' finishes or the restore puts the"
        error "  configuration back."
    fi
    error ""
    if [ "${_UPGRADE_STAGE:-core}" = "core" ]; then
        error "To retry after fixing the cause, run 'papaia-ctl upgrade --version=$target'"
        error "again: migrations that already succeeded are recorded and will be skipped, and"
        error "restore point $restore_point is kept."
    else
        error "To continue after fixing the cause:"
        error "    papaia-ctl upgrade --resume --config-dir=$CONFIG_DIR"
        error "  (with --identity=FILE when the upgrade has no rollback key)"
    fi
    exit 3
}

# ─────────────────────────────────────────────────────────────────────────
# papaia-ctl rollback: back to restore point R0 of the last upgrade in one command
# (lib/upgrade_stages.py, lib/rollback_key.py). Like `upgrade` it runs in two phases,
# split by the checkout:
#
#   phase 1 (this release)   the run and R0 from the upgrade state, the key (the run's
#                            rollback key, or --identity), the check that the key opens
#                            every archive of R0, the confirmation, `git checkout v<from>`
#   phase 2 (from release)   `restore --restart-clean` of R0 (erasure journals and the
#                            post-restore step run before the add-ons start), the run
#                            ends, the write lock and the rollback key go, `doctor`
#
# The key reaches phase 2 on standard input only, never as a file, argument or variable
# of the environment.
# ─────────────────────────────────────────────────────────────────────────
cmd_rollback() {
    local config_dir="$DEFAULT_CONFIG_DIR" restore_point="" identity="" assume_yes=0
    local accept_loss=0 insecure_images=0 resume_id="" resume_point=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --restore-point=*) restore_point="${1#*=}" ;;
            --identity=*)
                identity="${1#*=}"
                if [ -z "$identity" ]; then
                    error "--identity needs a key file or - (the key on standard input)."
                    exit 2
                fi
                ;;
            --accept-data-loss) accept_loss=1 ;;
            --insecure-images) insecure_images=1 ;;
            -y|--yes) assume_yes=1 ;;
            --resume-upgrade-id=*) resume_id="${1#*=}" ;;
            --resume-restore-point=*) resume_point="${1#*=}" ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for rollback: $1"; exit 2 ;;
        esac
        shift
    done
    CONFIG_DIR="$config_dir"
    _require_setup_done
    local mode
    mode="$(_topology_mode)" || exit 3
    if [ "$mode" = "distributed" ]; then
        error "'rollback' is not available for a distributed installation; go back with the"
        error "steps 'upgrade' printed (checkout, restore, upgrade --release-lock)."
        exit 2
    fi
    if [ -n "$resume_id" ]; then
        _rollback_apply "$resume_id" "$resume_point" "$insecure_images" "$assume_yes" \
            "$accept_loss"
        return 0
    fi
    if [ "$identity" = "-" ] && [ "$assume_yes" -eq 0 ]; then
        error "--identity=- reads the key from standard input, which then cannot answer"
        error "the confirmation. Add -y to confirm the rollback, or pass --identity=FILE."
        exit 2
    fi
    _upgrade_correlation
    py_cli rollback-key sweep || true

    local plan key value id="" from="" to="" point="" finished="" has_key=0
    local -a plan_flags=()
    [ -n "$restore_point" ] && plan_flags+=(--restore-point="$restore_point")
    plan="$(py_cli upgrade-stage rollback-plan ${plan_flags[@]+"${plan_flags[@]}"} \
        | tr -d '\r')" || exit 2
    while IFS=$'\t' read -r key value; do
        case "$key" in
            ID) id="$value" ;;
            FROM) from="$value" ;;
            TO) to="$value" ;;
            RESTORE_POINT) point="$value" ;;
            FINISHED) finished="$value" ;;
            ROLLBACK_KEY) has_key="$value" ;;
        esac
    done <<< "$plan"

    local commit
    if ! commit="$(git -C "$REPO_ROOT" rev-parse --verify --quiet "v$from^{commit}")" ||
            [ -z "$commit" ]; then
        error "The release tag v$from is not in $REPO_ROOT; nothing was changed."
        exit 2
    fi
    # Phase 2 runs the papaia-ctl of $from; a release without the command cannot finish it.
    if ! git -C "$REPO_ROOT" show "$commit:tools/lib/sh/upgrade.sh" 2>/dev/null \
            | grep -q '^cmd_rollback()'; then
        error "Release $from has no 'rollback' command. Go back step by step (nothing was changed):"
        error "    git -C $REPO_ROOT checkout v$from"
        error "    papaia-ctl restore --restore-point=$point --restart-clean --config-dir=$CONFIG_DIR"
        exit 2
    fi
    if [ -n "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=no)" ]; then
        error "The checkout has uncommitted changes to tracked files; the rollback has to move"
        error "it to v$from. Commit, stash or discard them first. Nothing was changed."
        exit 2
    fi

    # The key, checked against every archive of R0 before anything changes.
    local key_text=""
    if [ -n "$identity" ]; then
        key_text="$(py_cli backup-identities --identity="$identity")" || exit 2
    elif [ "$has_key" = "1" ]; then
        key_text="$(py_cli rollback-key identity --upgrade-id="$id")" || exit 2
        info "Using the rollback key of the upgrade to $to; no operator key is needed."
    else
        error "There is no rollback key for the upgrade to $to any more (its window ended or"
        error "it was deleted). Pass the backup key of a recipient: --identity=FILE, or"
        error "--identity=- together with -y. Nothing was changed."
        exit 2
    fi
    if ! printf '%s\n' "$key_text" | py_cli restore-resolve --restore-point="$point" --identity=- \
            >/dev/null; then
        error "The key does not open restore point $point; nothing was changed."
        exit 2
    fi

    warn "Rollback of the upgrade $from → $to: the checkout goes back to v$from, restore point"
    warn "$point is restored with --restart-clean (named volumes are deleted first) and the"
    warn "stack starts again."
    if [ "$finished" != "-" ] && [ "$accept_loss" -eq 0 ]; then
        warn "The upgrade finished at $finished and the installation accepted writes since"
        warn "then. They are lost: the installation goes back to the state before the upgrade."
        if [ "$assume_yes" -eq 0 ] && is_tty; then
            local answer=""
            read -r -p "Type 'ja' to accept the loss of these writes: " answer
            if [ "$answer" != "ja" ] && [ "$answer" != "yes" ]; then
                error "Aborted; nothing was changed."
                exit 3
            fi
        else
            error "Confirm the loss with --accept-data-loss (-y does not). Nothing was changed."
            exit 2
        fi
    fi
    if [ "$assume_yes" -eq 0 ]; then
        if ! is_tty; then
            error "Refusing to roll back without confirmation. Re-run with -y in non-interactive contexts."
            exit 2
        fi
        if ! confirm "Roll back to $from?" "N"; then
            error "Aborted."
            exit 3
        fi
    fi

    info "Moving the checkout back to v$from..."
    if ! git -C "$REPO_ROOT" checkout --detach --quiet "$commit"; then
        error "Could not check out v$from; nothing was changed."
        exit 3
    fi
    _upgrade_log "$to" "$from" rollback "restore_point=$point"
    # Confirmed above; the second phase checks the run, R0 and the data-loss answer again.
    local -a flags=(--config-dir="$CONFIG_DIR" --resume-upgrade-id="$id"
        --resume-restore-point="$point" -y)
    [ "$finished" != "-" ] && flags+=(--accept-data-loss)
    [ "$insecure_images" -eq 1 ] && flags+=(--insecure-images)
    # The papaia-ctl of $from, through the interpreter (see the handoff in cmd_upgrade);
    # the key travels on standard input.
    exec "${BASH:-bash}" "$REPO_ROOT/tools/papaia-ctl" rollback ${flags[@]+"${flags[@]}"} \
        < <(printf '%s\n' "$key_text")
}

# Phase 2 of `rollback`, from the release the upgrade started from. The key is on
# standard input. $1 upgrade id, $2 restore point R0, $3 1 for --insecure-images,
# $4 1 for -y, $5 1 for --accept-data-loss
#
# Reachable from the command line as well, so it never trusts phase 1: the point must be
# R0 of the recorded run with this id, and a finished upgrade needs the loss of its
# writes confirmed, before anything is restored.
_rollback_apply() {
    local id="$1" point="$2" insecure_images="${3:-0}" assume_yes="${4:-0}" accept_loss="${5:-0}"
    if [ -z "$point" ]; then
        error "--resume-upgrade-id needs --resume-restore-point; both are set by 'rollback'."
        exit 2
    fi
    _upgrade_correlation
    local plan key value plan_id="" finished=""
    plan="$(py_cli upgrade-stage rollback-plan --restore-point="$point" | tr -d '\r')" || exit 2
    while IFS=$'\t' read -r key value; do
        case "$key" in
            ID) plan_id="$value" ;;
            FINISHED) finished="$value" ;;
        esac
    done <<< "$plan"
    if [ "$plan_id" != "$id" ]; then
        error "Upgrade $id is not the run to roll back; nothing was changed."
        exit 2
    fi
    if [ "$finished" != "-" ] && [ "$accept_loss" -eq 0 ]; then
        error "The upgrade finished at $finished; confirm the loss of the writes since then"
        error "with --accept-data-loss. Nothing was changed."
        exit 2
    fi
    if [ "$assume_yes" -eq 0 ]; then
        error "Refusing to restore $point without confirmation; run 'papaia-ctl rollback'."
        exit 2
    fi
    info "Continuing the rollback with the papaia-ctl of the checkout."
    # The add-ons' erasure journals run with the trigger `rollback` (lib/module_actions.py).
    # shellcheck disable=SC2034  # read by cmd_restore in lib/sh/backup.sh
    RESTORE_TRIGGER="rollback"
    local -a flags=(--config-dir="$CONFIG_DIR" --restore-point="$point" --restart-clean
        --identity=- -y)
    [ "$insecure_images" = "1" ] && flags+=(--insecure-images)
    cmd_restore ${flags[@]+"${flags[@]}"}
    if ! py_cli upgrade-stage rollback-done --upgrade-id="$id"; then
        error "Restore point $point was restored, but the run could not be closed; the write"
        error "lock stays. Check the installation, then run 'papaia-ctl upgrade --release-lock -y'."
        exit 3
    fi
    local rc=0
    cmd_doctor --config-dir="$CONFIG_DIR" || rc=$?
    if [ "$rc" -ne 0 ]; then
        error "The rollback is complete, but doctor reports a failure (above)."
        exit 3
    fi
    success "rollback complete: back at restore point $point."
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

# Verifies a signed suite bill of materials (docs/compatibility.md). Read-only and
# independent of an installation, so it needs no setup.
cmd_suite_verify() {
    local -a extra=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --bom=*) extra+=(--bom="${1#*=}") ;;
            --signature=*) extra+=(--signature="${1#*=}") ;;
            --key=*) extra+=(--key="${1#*=}") ;;
            --fingerprint=*) extra+=(--fingerprint="${1#*=}") ;;
            --suite=*) extra+=(--suite="${1#*=}") ;;
            --scope=*) extra+=(--scope="${1#*=}") ;;
            --json) extra+=(--json) ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for suite verify: $1"; exit 2 ;;
        esac
        shift
    done
    CONFIG_DIR="$DEFAULT_CONFIG_DIR"
    if [ -n "${TEST_TRUST_ANCHOR:-}" ]; then
        extra+=(--test-trust-anchor="${TEST_TRUST_ANCHOR:-}")
        [ -n "$IMAGES_CORRELATION_ID" ] && extra+=(--correlation-id="$IMAGES_CORRELATION_ID")
    fi
    py_cli suite-verify ${extra[@]+"${extra[@]}"}
}
