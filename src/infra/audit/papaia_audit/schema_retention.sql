-- papaia-audit retention, deletion lock and SIEM read positions (docs/audit.md,
-- "Retention" and "SIEM"). `python -m papaia_audit schema` runs it once, as the database
-- owner, in the transaction of schema.sql, when audit.anchor does not exist yet (a new
-- store, or a store of an earlier release).
--
-- A chain is only shortened at its start, by audit.prune and nothing else: it records the
-- last removed event as the source's anchor (verify continues from there) and refuses to
-- remove an event younger than the limit, an event of a person under a deletion lock, or
-- an event a SIEM target has not taken yet (also a target no longer configured, until
-- `audit siem skip` releases it). The role audit_retention may only run audit.prune and
-- write the retention run's own events.

CREATE ROLE audit_retention LOGIN;
GRANT CONNECT ON DATABASE audit TO audit_retention;
GRANT USAGE ON SCHEMA audit TO audit_retention;

-- The last removed event of each source.
CREATE TABLE audit.anchor (
    source     text           PRIMARY KEY,
    seq        bigint         NOT NULL CHECK (seq >= 1),
    source_seq bigint         NOT NULL CHECK (source_seq >= 1),
    hash       bytea          NOT NULL CHECK (octet_length(hash) = 32),
    removed_at timestamptz(3) NOT NULL
);

-- Deletion lock (sicherheit §1.15): set and lifted by two different persons, with a
-- reason; rows are never removed, a lift is recorded in the row.
CREATE TABLE audit.legal_hold (
    id                uuid           PRIMARY KEY,
    sub               text           NOT NULL CHECK (char_length(sub) BETWEEN 1 AND 255),
    reason            text           NOT NULL CHECK (char_length(reason) BETWEEN 20 AND 1000),
    set_by            text           NOT NULL,
    set_confirmed_by  text           NOT NULL CHECK (set_confirmed_by <> set_by),
    set_at            timestamptz(3) NOT NULL,
    lifted_by         text,
    lift_confirmed_by text,
    lifted_at         timestamptz(3),
    CHECK ((lifted_at IS NULL) = (lifted_by IS NULL)
           AND (lifted_at IS NULL) = (lift_confirmed_by IS NULL)),
    CHECK (lift_confirmed_by IS NULL OR lift_confirmed_by <> lifted_by)
);
CREATE UNIQUE INDEX legal_hold_active ON audit.legal_hold (sub) WHERE lifted_at IS NULL;

-- SIEM targets and how far each has taken the events of each source.
CREATE TABLE audit.export_target (
    target text    PRIMARY KEY CHECK (char_length(target) BETWEEN 1 AND 300),
    active boolean NOT NULL
);
CREATE TABLE audit.export_cursor (
    target     text           NOT NULL REFERENCES audit.export_target (target),
    source     text           NOT NULL,
    seq        bigint         NOT NULL CHECK (seq >= 0),
    updated_at timestamptz(3) NOT NULL,
    PRIMARY KEY (target, source)
);

-- Settings of the service as last seen (retention, SIEM); a change is an event.
CREATE TABLE audit.setting (
    key        text           PRIMARY KEY CHECK (key ~ '^audit\.[a-z_]{1,60}$'),
    value      text           NOT NULL CHECK (char_length(value) <= 300),
    changed_at timestamptz(3) NOT NULL
);

CREATE INDEX event_sub_seq ON audit.event (sub, source, seq) WHERE sub IS NOT NULL;

-- Events stay unchangeable; only audit.prune removes them, at the start of a chain.
DROP TRIGGER event_append_only ON audit.event;
CREATE TRIGGER event_no_update BEFORE UPDATE ON audit.event
    FOR EACH ROW EXECUTE FUNCTION audit.refuse_change();

CREATE FUNCTION audit.refuse_delete_outside_prune() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('papaia_audit.prune', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION 'audit events are only removed by a retention run'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN OLD;
END
$$;
CREATE TRIGGER event_delete_only_by_prune BEFORE DELETE ON audit.event
    FOR EACH ROW EXECUTE FUNCTION audit.refuse_delete_outside_prune();

CREATE TRIGGER anchor_no_delete BEFORE DELETE ON audit.anchor
    FOR EACH ROW EXECUTE FUNCTION audit.refuse_change();
CREATE TRIGGER legal_hold_no_delete BEFORE DELETE ON audit.legal_hold
    FOR EACH ROW EXECUTE FUNCTION audit.refuse_change();
CREATE TRIGGER legal_hold_no_truncate BEFORE TRUNCATE ON audit.legal_hold
    FOR EACH STATEMENT EXECUTE FUNCTION audit.refuse_change();
CREATE TRIGGER anchor_no_truncate BEFORE TRUNCATE ON audit.anchor
    FOR EACH STATEMENT EXECUTE FUNCTION audit.refuse_change();

-- audit.append as before, continuing from the anchor once a chain's start was removed. A
-- source_seq at or below the anchor was stored and removed: a repeat.
CREATE OR REPLACE FUNCTION audit.append(p_source text, p_canonical text) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_body       jsonb := p_canonical::jsonb;
    v_source_seq bigint := (v_body ->> 'source_seq')::bigint;
    v_seq        bigint;
    v_last_seq   bigint;
    v_last_ss    bigint;
    v_prev       bytea;
    v_anchor     audit.anchor%ROWTYPE;
BEGIN
    IF p_source !~ '^[a-z][a-z0-9-]{0,62}$' OR v_source_seq IS NULL THEN
        RAISE EXCEPTION 'invalid source or source_seq' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext(p_source));

    SELECT e.seq INTO v_seq FROM audit.event e
        WHERE e.source = p_source AND e.source_seq = v_source_seq;
    IF FOUND THEN
        RETURN v_seq;
    END IF;
    SELECT * INTO v_anchor FROM audit.anchor a WHERE a.source = p_source;
    IF FOUND AND v_source_seq <= v_anchor.source_seq THEN
        RETURN v_anchor.seq - (v_anchor.source_seq - v_source_seq);
    END IF;

    SELECT e.seq, e.source_seq, e.hash INTO v_last_seq, v_last_ss, v_prev FROM audit.event e
        WHERE e.source = p_source ORDER BY e.seq DESC LIMIT 1;
    IF NOT FOUND AND v_anchor.source IS NOT NULL THEN
        v_last_seq := v_anchor.seq;
        v_last_ss := v_anchor.source_seq;
        v_prev := v_anchor.hash;
    END IF;
    IF v_source_seq <> coalesce(v_last_ss, 0) + 1 THEN
        RAISE EXCEPTION 'source_seq is not the next one of the source' USING ERRCODE = 'PA001';
    END IF;

    v_seq := coalesce(v_last_seq, 0) + 1;
    v_prev := coalesce(v_prev, '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea);
    INSERT INTO audit.event (source, seq, source_seq, time, prev_hash, hash, sub, event,
                             correlation_id, catalog_id, result, body)
    VALUES (p_source, v_seq, v_source_seq, (v_body ->> 'time')::timestamptz, v_prev,
            sha256(v_prev || convert_to(p_canonical, 'UTF8')), v_body ->> 'sub',
            v_body ->> 'event', v_body ->> 'correlation_id', v_body ->> 'catalog_id',
            v_body ->> 'result', v_body);
    RETURN v_seq;
END
$$;

-- The next source_seq of a source, under the lock of audit.append, which the caller runs
-- in the same transaction: papaia-audit writes its own events with it.
CREATE FUNCTION audit.next_seq(p_source text) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext(p_source));
    RETURN coalesce((SELECT max(e.source_seq) FROM audit.event e WHERE e.source = p_source),
                    (SELECT a.source_seq FROM audit.anchor a WHERE a.source = p_source),
                    0) + 1;
END
$$;

-- The read API's next source_seq (schema_read.sql, applied before this file) continues
-- from the anchor as well, once retention has emptied the chain of papaia-audit.
CREATE OR REPLACE FUNCTION audit.next_source_seq(p_source text) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RETURN audit.next_seq(p_source);
END
$$;

-- An event of the retention run or a settings change, into the chain of papaia-audit.
CREATE FUNCTION audit.append_own(p_canonical text) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_body jsonb := p_canonical::jsonb;
BEGIN
    IF NOT ((v_body ->> 'writer' = 'papaia-audit/retention' AND v_body ->> 'event' = 'retention_run')
            OR (v_body ->> 'writer' = 'papaia-audit/config' AND v_body ->> 'event' = 'config_changed'))
    THEN
        RAISE EXCEPTION 'not an event of the retention run' USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN audit.append('papaia-audit', p_canonical);
END
$$;

-- Removes the events of a source up to p_upto_seq. Returns the number removed and the
-- anchor afterwards. Refuses (SQLSTATE PA002) when one of them is younger than p_months
-- months, belongs to a person under a deletion lock, or was not taken by a SIEM target
-- yet, active or not.
CREATE FUNCTION audit.prune(p_source text, p_upto_seq bigint, p_months integer,
                            OUT removed bigint, OUT anchor_seq bigint, OUT anchor_hash bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_anchor audit.anchor%ROWTYPE;
    v_last   audit.event%ROWTYPE;
BEGIN
    IF p_months IS NULL OR p_months NOT BETWEEN 6 AND 36 OR p_upto_seq IS NULL THEN
        RAISE EXCEPTION 'invalid retention' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext(p_source));
    SELECT * INTO v_anchor FROM audit.anchor a WHERE a.source = p_source;
    removed := 0;
    anchor_seq := v_anchor.seq;
    anchor_hash := v_anchor.hash;
    IF p_upto_seq <= coalesce(v_anchor.seq, 0) THEN
        RETURN;
    END IF;
    SELECT * INTO v_last FROM audit.event e WHERE e.source = p_source AND e.seq = p_upto_seq;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no such event' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF EXISTS (SELECT 1 FROM audit.event e WHERE e.source = p_source AND e.seq <= p_upto_seq
               AND e.time >= now() - make_interval(months => p_months)) THEN
        RAISE EXCEPTION 'events within the retention period' USING ERRCODE = 'PA002';
    END IF;
    IF EXISTS (SELECT 1 FROM audit.event e JOIN audit.legal_hold h
                   ON h.sub = e.sub AND h.lifted_at IS NULL
               WHERE e.source = p_source AND e.seq <= p_upto_seq) THEN
        RAISE EXCEPTION 'events under a deletion lock' USING ERRCODE = 'PA002';
    END IF;
    IF EXISTS (SELECT 1 FROM audit.export_target t
               LEFT JOIN audit.export_cursor c ON c.target = t.target AND c.source = p_source
               WHERE coalesce(c.seq, 0) < p_upto_seq) THEN
        RAISE EXCEPTION 'events not yet taken by a SIEM target' USING ERRCODE = 'PA002';
    END IF;

    INSERT INTO audit.anchor (source, seq, source_seq, hash, removed_at)
        VALUES (p_source, v_last.seq, v_last.source_seq, v_last.hash, clock_timestamp())
        ON CONFLICT (source) DO UPDATE SET seq = EXCLUDED.seq, source_seq = EXCLUDED.source_seq,
            hash = EXCLUDED.hash, removed_at = EXCLUDED.removed_at;
    PERFORM set_config('papaia_audit.prune', 'on', true);
    DELETE FROM audit.event e WHERE e.source = p_source AND e.seq <= p_upto_seq;
    GET DIAGNOSTICS removed = ROW_COUNT;
    PERFORM set_config('papaia_audit.prune', 'off', true);
    anchor_seq := v_last.seq;
    anchor_hash := v_last.hash;
END
$$;

-- Deletion lock: set and lift, each by two different persons. No role executes these yet:
-- the route that proves both persons by their tokens and writes the legal_hold_set or
-- legal_hold_lifted event in the same transaction comes with the store's person API, which
-- grants them to a role of its own. Until then only the database owner can set a lock.
CREATE FUNCTION audit.legal_hold_set(p_id uuid, p_sub text, p_reason text, p_by text,
                                     p_confirmed_by text) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    INSERT INTO audit.legal_hold (id, sub, reason, set_by, set_confirmed_by, set_at)
    VALUES (p_id, p_sub, p_reason, p_by, p_confirmed_by, clock_timestamp());
$$;

CREATE FUNCTION audit.legal_hold_lift(p_sub text, p_by text, p_confirmed_by text)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    UPDATE audit.legal_hold SET lifted_by = p_by, lift_confirmed_by = p_confirmed_by,
        lifted_at = clock_timestamp()
        WHERE sub = p_sub AND lifted_at IS NULL;
    RETURN FOUND;
END
$$;

-- The configured SIEM targets: those named become active, every other one inactive. An
-- inactive target is no longer sent to but still holds back what it has not taken.
CREATE FUNCTION audit.export_targets_set(p_targets text[]) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    INSERT INTO audit.export_target (target, active)
        SELECT t, true FROM unnest(p_targets) AS t
        ON CONFLICT (target) DO UPDATE SET active = true;
    UPDATE audit.export_target SET active = false WHERE NOT (target = ANY (p_targets));
$$;

-- Moves a read position forward (never back) after the target took the events.
CREATE FUNCTION audit.export_advance(p_target text, p_source text, p_seq bigint) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    INSERT INTO audit.export_cursor (target, source, seq, updated_at)
        VALUES (p_target, p_source, p_seq, clock_timestamp())
        ON CONFLICT (target, source) DO UPDATE SET seq = greatest(audit.export_cursor.seq,
            EXCLUDED.seq), updated_at = EXCLUDED.updated_at;
$$;

CREATE FUNCTION audit.setting_put(p_key text, p_value text) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    INSERT INTO audit.setting (key, value, changed_at) VALUES (p_key, p_value, clock_timestamp())
        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, changed_at = EXCLUDED.changed_at;
$$;

REVOKE ALL ON FUNCTION audit.refuse_delete_outside_prune() FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.next_seq(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.append_own(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.prune(text, bigint, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.legal_hold_set(uuid, text, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.legal_hold_lift(text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.export_targets_set(text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.export_advance(text, text, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.setting_put(text, text) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION audit.prune(text, bigint, integer) TO audit_retention;
GRANT EXECUTE ON FUNCTION audit.next_seq(text) TO audit_retention;
GRANT EXECUTE ON FUNCTION audit.append_own(text) TO audit_retention;
GRANT EXECUTE ON FUNCTION audit.setting_put(text, text) TO audit_retention;
GRANT EXECUTE ON FUNCTION audit.export_targets_set(text[]) TO audit_ingest;
GRANT EXECUTE ON FUNCTION audit.export_advance(text, text, bigint) TO audit_ingest;
GRANT SELECT ON audit.anchor, audit.legal_hold, audit.export_target, audit.export_cursor,
    audit.setting TO audit_read;
