-- papaia-audit identity map, delivery state of the SIEM targets and `audit siem skip`
-- (docs/audit.md, "SIEM" and "Identity map"). `python -m papaia_audit schema` runs it once,
-- as the database owner, in the transaction of the other schema files, when
-- audit.person_identity does not exist yet (a new store, or one of an earlier release).
--
-- Nothing here removes an event. A skip only moves read positions forward, with a reason
-- that stays in audit.export_skip; the events stay until retention removes them.

-- The upstream provider's ids of a person (tenant `tid`, object `oid`) and the user
-- name, fed by papaia-lifecycle. Read only by the read API with a ticket (audit idmap)
-- and by the SIEM export with identity `upstream_oid`.
CREATE TABLE audit.person_identity (
    sub        text           PRIMARY KEY
                              CHECK (sub ~ '^[A-Za-z0-9][A-Za-z0-9._:@|+-]{0,254}$'),
    username   text           CHECK (username IS NULL OR (char_length(username) BETWEEN 1 AND 255
                                     AND username !~ '[[:cntrl:]]')),
    tid        text           CHECK (tid IS NULL OR tid ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    oid        text           CHECK (oid IS NULL OR oid ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    updated_at timestamptz(3) NOT NULL,
    CHECK ((tid IS NULL) = (oid IS NULL))
);
CREATE UNIQUE INDEX person_identity_upstream ON audit.person_identity (tid, oid)
    WHERE tid IS NOT NULL;

-- When a target last took everything, and since when its deliveries fail.
ALTER TABLE audit.export_target
    ADD COLUMN delivered_at  timestamptz(3),
    ADD COLUMN failing_since timestamptz(3);

-- Every read position the operator moved past undelivered events, with the reason.
CREATE TABLE audit.export_skip (
    correlation_id text           NOT NULL CHECK (correlation_id ~ '^[A-Za-z0-9-]{1,64}$'),
    target         text           NOT NULL REFERENCES audit.export_target (target),
    source         text           NOT NULL,
    from_seq       bigint         NOT NULL CHECK (from_seq >= 0),
    until_seq      bigint         NOT NULL,
    released       bigint         NOT NULL CHECK (released >= 0),
    reason         text           NOT NULL
                                  CHECK (char_length(btrim(reason)) BETWEEN 20 AND 1000),
    skipped_at     timestamptz(3) NOT NULL,
    PRIMARY KEY (correlation_id, target, source),
    CHECK (until_seq > from_seq)
);
CREATE TRIGGER export_skip_unchangeable BEFORE UPDATE OR DELETE ON audit.export_skip
    FOR EACH ROW EXECUTE FUNCTION audit.refuse_change();
CREATE TRIGGER export_skip_no_truncate BEFORE TRUNCATE ON audit.export_skip
    FOR EACH STATEMENT EXECUTE FUNCTION audit.refuse_change();

-- The outages the watch has mailed (a SIEM target by its name, the volume as
-- `volume:papaia-audit-db`): one mail per outage, also across a restart. Cleared by the
-- watch once the target or the volume is fine again.
CREATE TABLE audit.alert_state (
    key       text           PRIMARY KEY CHECK (char_length(key) BETWEEN 1 AND 300
                                                AND key !~ '[[:cntrl:][:space:]]'),
    raised_at timestamptz(3) NOT NULL
);

-- The last hourly verification of each chain, for `siem-status` (doctor siem), which
-- would otherwise have to walk every chain within its timeout.
CREATE TABLE audit.verify_state (
    source      text           PRIMARY KEY CHECK (source ~ '^[a-z][a-z0-9-]{0,62}$'),
    valid       boolean        NOT NULL,
    broken_at   bigint         CHECK (broken_at IS NULL OR broken_at >= 1),
    verified_at timestamptz(3) NOT NULL,
    CHECK (valid = (broken_at IS NULL))
);

CREATE FUNCTION audit.alert_mark(p_key text) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    INSERT INTO audit.alert_state (key, raised_at) VALUES (p_key, clock_timestamp())
        ON CONFLICT (key) DO NOTHING;
$$;

CREATE FUNCTION audit.alert_clear(p_keys text[]) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    DELETE FROM audit.alert_state WHERE key = ANY(p_keys);
$$;

CREATE FUNCTION audit.verify_record(p_source text, p_valid boolean, p_broken_at bigint)
RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    INSERT INTO audit.verify_state (source, valid, broken_at, verified_at)
        VALUES (p_source, p_valid, p_broken_at, clock_timestamp())
        ON CONFLICT (source) DO UPDATE SET valid = EXCLUDED.valid,
            broken_at = EXCLUDED.broken_at, verified_at = EXCLUDED.verified_at;
$$;

-- One person's ids. An upstream id names one person: when it moves to another `sub`, the
-- old link is cleared first.
CREATE FUNCTION audit.identity_put(p_sub text, p_username text, p_tid text, p_oid text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF p_tid IS NOT NULL THEN
        UPDATE audit.person_identity SET tid = NULL, oid = NULL, updated_at = clock_timestamp()
            WHERE tid = p_tid AND oid = p_oid AND sub <> p_sub;
    END IF;
    INSERT INTO audit.person_identity (sub, username, tid, oid, updated_at)
        VALUES (p_sub, p_username, p_tid, p_oid, clock_timestamp())
        ON CONFLICT (sub) DO UPDATE SET username = EXCLUDED.username, tid = EXCLUDED.tid,
            oid = EXCLUDED.oid, updated_at = EXCLUDED.updated_at;
END
$$;

-- One export cycle: the target took everything, or a batch failed.
CREATE FUNCTION audit.export_delivery(p_target text, p_ok boolean) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    UPDATE audit.export_target
        SET delivered_at = CASE WHEN p_ok THEN clock_timestamp() ELSE delivered_at END,
            failing_since = CASE WHEN p_ok THEN NULL
                                 ELSE coalesce(failing_since, clock_timestamp()) END
        WHERE target = p_target;
$$;

-- Moves the read positions of `p_source` up to `p_until` for the named target, or for
-- every target, active or not, that has not taken them; with a reason (SQLSTATE PA003
-- otherwise). Returns how many positions moved and how many events they released. The
-- caller appends the skip events in the same transaction.
CREATE FUNCTION audit.export_skip(p_source text, p_until bigint, p_target text, p_reason text,
                                  p_correlation_id text,
                                  OUT target text, OUT from_seq bigint, OUT released bigint)
RETURNS SETOF record
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_last bigint;
    v_row  record;
BEGIN
    IF p_reason IS NULL OR char_length(btrim(p_reason)) NOT BETWEEN 20 AND 1000 THEN
        RAISE EXCEPTION 'a skip needs a reason of 20 to 1000 characters' USING ERRCODE = 'PA003';
    END IF;
    IF p_source IS NULL OR p_source !~ '^[a-z][a-z0-9-]{0,62}$' OR p_until IS NULL
       OR p_until < 1 THEN
        RAISE EXCEPTION 'invalid source or seq' USING ERRCODE = 'PA003';
    END IF;
    IF p_target IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM audit.export_target t WHERE t.target = p_target) THEN
        RAISE EXCEPTION 'no such SIEM target' USING ERRCODE = 'PA003';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext(p_source));
    v_last := greatest((SELECT max(e.seq) FROM audit.event e WHERE e.source = p_source),
                       (SELECT a.seq FROM audit.anchor a WHERE a.source = p_source));
    IF v_last IS NULL OR p_until > v_last THEN
        RAISE EXCEPTION 'the source has no event with this seq' USING ERRCODE = 'PA003';
    END IF;
    FOR v_row IN
        SELECT t.target AS name, coalesce(c.seq, 0) AS position
        FROM audit.export_target t
        LEFT JOIN audit.export_cursor c ON c.target = t.target AND c.source = p_source
        WHERE (p_target IS NULL OR t.target = p_target) AND coalesce(c.seq, 0) < p_until
        ORDER BY t.target
    LOOP
        target := v_row.name;
        from_seq := v_row.position;
        released := (SELECT count(*) FROM audit.event e WHERE e.source = p_source
                     AND e.seq > v_row.position AND e.seq <= p_until);
        INSERT INTO audit.export_skip (correlation_id, target, source, from_seq, until_seq,
                                       released, reason, skipped_at)
            VALUES (p_correlation_id, v_row.name, p_source, v_row.position, p_until, released,
                    btrim(p_reason), clock_timestamp());
        PERFORM audit.export_advance(v_row.name, p_source, p_until);
        RETURN NEXT;
    END LOOP;
END
$$;

-- The own events of papaia-audit: the retention run, settings changes, and now the skip
-- (a settings change that discards deliveries) and the warning mails (a send: a SIEM
-- target that takes nothing, the volume of the store at 95 %).
CREATE OR REPLACE FUNCTION audit.append_own(p_canonical text) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_body jsonb := p_canonical::jsonb;
BEGIN
    IF NOT ((v_body ->> 'writer' = 'papaia-audit/retention' AND v_body ->> 'event' = 'retention_run')
            OR (v_body ->> 'writer' = 'papaia-audit/config' AND v_body ->> 'event' = 'config_changed')
            OR (v_body ->> 'writer' = 'papaia-audit/siem' AND v_body ->> 'event' = 'config_changed'
                AND v_body ->> 'operation' = 'siem.skip')
            OR (v_body ->> 'writer' = 'papaia-audit/siem' AND v_body ->> 'event' = 'operation'
                AND v_body ->> 'operation' IN ('siem.alert_mail', 'store.disk_alert_mail')))
    THEN
        RAISE EXCEPTION 'not an event of the retention run' USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN audit.append('papaia-audit', p_canonical);
END
$$;

REVOKE ALL ON FUNCTION audit.identity_put(text, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.export_delivery(text, boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.export_skip(text, bigint, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.alert_mark(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.alert_clear(text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.verify_record(text, boolean, bigint) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION audit.identity_put(text, text, text, text) TO audit_ingest;
GRANT EXECUTE ON FUNCTION audit.export_delivery(text, boolean) TO audit_ingest;
GRANT EXECUTE ON FUNCTION audit.export_skip(text, bigint, text, text, text) TO audit_retention;
GRANT EXECUTE ON FUNCTION audit.alert_mark(text) TO audit_retention;
GRANT EXECUTE ON FUNCTION audit.alert_clear(text[]) TO audit_retention;
GRANT EXECUTE ON FUNCTION audit.verify_record(text, boolean, bigint) TO audit_retention;
GRANT SELECT ON audit.person_identity, audit.export_skip, audit.alert_state,
    audit.verify_state TO audit_read;
