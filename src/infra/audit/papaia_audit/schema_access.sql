-- papaia-audit person routes of the permission report and the deletion lock (docs/audit.md,
-- "Permission report" and "Deletion lock"). `python -m papaia_audit schema` runs it once,
-- as the database owner, in the transaction of schema.sql, when audit.legal_hold_request
-- does not exist yet (a new store, or a store of an earlier release). It needs
-- schema_read.sql and schema_retention.sql, which run before it.
--
-- A deletion lock is set and lifted by two different persons. The first asks
-- (audit.legal_hold_request), the second confirms within 24 hours; audit.legal_hold_confirm
-- checks both, calls audit.legal_hold_set or audit.legal_hold_lift and appends the
-- legal_hold_set or legal_hold_lifted event itself, after checking that it names the
-- confirming person and the person of the request. So no lock changes without its event,
-- and the role audit_hold cannot write such an event without a change. Only audit_hold
-- reaches these functions; on its own it may append approval_changed of the lock only
-- (writer papaia-audit/hold). audit_ingest gets none of them; it keeps EXECUTE on
-- audit.append for the sources it serves, which does not yet refuse a lock event body
-- (follow-up CORE-041-F5 in docs/audit.md).
--
-- A recertification row (audit.access_confirmation) records that the administration
-- confirmed one row of the permission report with the digest of the content it saw. Rows
-- are only added; the report shows the newest per key.

CREATE ROLE audit_hold LOGIN;
GRANT CONNECT ON DATABASE audit TO audit_hold;
GRANT USAGE ON SCHEMA audit TO audit_hold;

CREATE TABLE audit.legal_hold_request (
    id           uuid           PRIMARY KEY,
    action       text           NOT NULL CHECK (action IN ('set', 'lift')),
    sub          text           NOT NULL CHECK (char_length(sub) BETWEEN 1 AND 255),
    reason       text           NOT NULL CHECK (char_length(reason) BETWEEN 20 AND 1000),
    requested_by text           NOT NULL,
    requested_at timestamptz(3) NOT NULL,
    state        text           NOT NULL DEFAULT 'open'
                                CHECK (state IN ('open', 'confirmed', 'rejected')),
    decided_by   text,
    decided_at   timestamptz(3),
    CHECK ((state = 'open') = (decided_by IS NULL AND decided_at IS NULL)),
    CHECK (state <> 'confirmed' OR decided_by <> requested_by)
);
CREATE INDEX legal_hold_request_open ON audit.legal_hold_request (requested_at)
    WHERE state = 'open';

CREATE TABLE audit.access_confirmation (
    key          text           NOT NULL
                                CHECK (key ~ '^(person|system):[A-Za-z0-9][A-Za-z0-9._:@+-]{0,254}$'),
    digest       text           NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
    confirmed_by text           NOT NULL,
    confirmed_at timestamptz(3) NOT NULL,
    CHECK (key <> 'person:' || confirmed_by)
);
CREATE INDEX access_confirmation_key ON audit.access_confirmation (key, confirmed_at);

CREATE TRIGGER legal_hold_request_no_delete BEFORE DELETE ON audit.legal_hold_request
    FOR EACH ROW EXECUTE FUNCTION audit.refuse_change();
CREATE TRIGGER legal_hold_request_no_truncate BEFORE TRUNCATE ON audit.legal_hold_request
    FOR EACH STATEMENT EXECUTE FUNCTION audit.refuse_change();
CREATE TRIGGER access_confirmation_no_change BEFORE UPDATE OR DELETE ON audit.access_confirmation
    FOR EACH ROW EXECUTE FUNCTION audit.refuse_change();
CREATE TRIGGER access_confirmation_no_truncate BEFORE TRUNCATE ON audit.access_confirmation
    FOR EACH STATEMENT EXECUTE FUNCTION audit.refuse_change();

CREATE FUNCTION audit.legal_hold_request_add(p_id uuid, p_action text, p_sub text,
                                             p_reason text, p_by text, p_at timestamptz)
RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    INSERT INTO audit.legal_hold_request (id, action, sub, reason, requested_by, requested_at)
    VALUES (p_id, p_action, p_sub, p_reason, p_by, p_at);
$$;

-- Rejects an open request; false when it is no longer open.
CREATE FUNCTION audit.legal_hold_request_reject(p_id uuid, p_by text, p_at timestamptz)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    UPDATE audit.legal_hold_request SET state = 'rejected', decided_by = p_by, decided_at = p_at
        WHERE id = p_id AND state = 'open';
    RETURN FOUND;
END
$$;

-- Confirms an open request by a second person, sets or lifts the lock and appends
-- p_canonical, its event. False (and nothing changed) when the request is no longer open,
-- is older than 24 hours by the database clock, the lock to set exists or the lock to lift
-- does not. The person who asked can never confirm; an event that does not describe this
-- confirmation is refused.
CREATE FUNCTION audit.legal_hold_confirm(p_id uuid, p_by text, p_at timestamptz,
                                         p_canonical text)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_request audit.legal_hold_request%ROWTYPE;
    v_body    jsonb := p_canonical::jsonb;
BEGIN
    SELECT * INTO v_request FROM audit.legal_hold_request r
        WHERE r.id = p_id AND r.state = 'open' FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    IF v_request.requested_by = p_by THEN
        RAISE EXCEPTION 'a deletion lock needs a second person' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF greatest(p_at, clock_timestamp()) >= v_request.requested_at + interval '24 hours' THEN
        RETURN false;
    END IF;
    IF NOT (v_body ->> 'writer' = 'papaia-audit/hold'
            AND v_body ->> 'event' = CASE v_request.action WHEN 'set' THEN 'legal_hold_set'
                                                            ELSE 'legal_hold_lifted' END
            AND v_body ->> 'result' = 'allowed'
            AND v_body ->> 'sub' = p_by
            AND v_body -> 'object_ref' ->> 'type' = 'person'
            AND v_body -> 'object_ref' ->> 'id' = v_request.sub)
    THEN
        RAISE EXCEPTION 'not the event of this confirmation' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF v_request.action = 'set' THEN
        IF EXISTS (SELECT 1 FROM audit.legal_hold h
                   WHERE h.sub = v_request.sub AND h.lifted_at IS NULL) THEN
            RETURN false;
        END IF;
        PERFORM audit.legal_hold_set(v_request.id, v_request.sub, v_request.reason,
                                     v_request.requested_by, p_by);
    ELSIF NOT audit.legal_hold_lift(v_request.sub, v_request.requested_by, p_by) THEN
        RETURN false;
    END IF;
    UPDATE audit.legal_hold_request SET state = 'confirmed', decided_by = p_by, decided_at = p_at
        WHERE id = p_id;
    PERFORM audit.append('papaia-audit', p_canonical);
    RETURN true;
END
$$;

-- An event of a lock request (asked or rejected), into the chain of papaia-audit; nothing
-- else. The events of a lock change are appended by audit.legal_hold_confirm only.
CREATE FUNCTION audit.append_hold(p_canonical text) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_body jsonb := p_canonical::jsonb;
BEGIN
    IF NOT (v_body ->> 'writer' = 'papaia-audit/hold' AND v_body ->> 'event' = 'approval_changed')
    THEN
        RAISE EXCEPTION 'not an event of a lock request' USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN audit.append('papaia-audit', p_canonical);
END
$$;

CREATE FUNCTION audit.access_confirmation_add(p_key text, p_digest text, p_by text,
                                              p_at timestamptz) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    INSERT INTO audit.access_confirmation (key, digest, confirmed_by, confirmed_at)
    VALUES (p_key, p_digest, p_by, p_at);
$$;

REVOKE ALL ON FUNCTION audit.legal_hold_request_add(uuid, text, text, text, text, timestamptz)
    FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.legal_hold_request_reject(uuid, text, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.legal_hold_confirm(uuid, text, timestamptz, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.append_hold(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.access_confirmation_add(text, text, text, timestamptz) FROM PUBLIC;

-- The lock is reached through legal_hold_confirm only, which proves the second person;
-- audit.legal_hold_set and audit.legal_hold_lift keep no direct grant.
GRANT EXECUTE ON FUNCTION audit.legal_hold_request_add(uuid, text, text, text, text, timestamptz)
    TO audit_hold;
GRANT EXECUTE ON FUNCTION audit.legal_hold_request_reject(uuid, text, timestamptz) TO audit_hold;
GRANT EXECUTE ON FUNCTION audit.legal_hold_confirm(uuid, text, timestamptz, text)
    TO audit_hold;
GRANT EXECUTE ON FUNCTION audit.append_hold(text) TO audit_hold;
GRANT EXECUTE ON FUNCTION audit.next_source_seq(text) TO audit_hold;
GRANT EXECUTE ON FUNCTION audit.access_confirmation_add(text, text, text, timestamptz)
    TO audit_ingest;
GRANT SELECT ON audit.legal_hold_request, audit.access_confirmation TO audit_read;
