-- papaia-audit requests for information and erasure of a person without an account
-- (docs/person-requests.md, "Requests and confirmation"). `python -m papaia_audit schema`
-- runs it once, as the database owner, in the transaction of schema.sql, when
-- audit.person_request does not exist yet (a new store, or a store of an earlier
-- release). It needs schema_access.sql (role audit_hold), which runs before it.
--
-- The host files a request (audit.person_request_add); the person it names as confirming
-- confirms it (audit.person_request_decide), never the requesting one; the host runs it
-- (audit.person_request_advance: confirmed -> running -> done | partial) and takes the
-- key of an export once (audit.person_request_take_key). Every function appends its own
-- event after checking that it describes this change, so no state changes without its
-- event. The role audit_hold, which already carries the two-person deletion lock, is
-- the only one that reaches these functions. Rows are never deleted.

CREATE TABLE audit.person_request (
    id           uuid           PRIMARY KEY,
    operation    text           NOT NULL CHECK (operation IN ('export', 'erase')),
    sub          text           NOT NULL CHECK (char_length(sub) BETWEEN 1 AND 255),
    transfer_to  text           CHECK (transfer_to IS NULL OR
                                       (operation = 'erase' AND transfer_to <> sub)),
    requested_by text           NOT NULL,
    confirmed_by text           NOT NULL,
    requested_at timestamptz(3) NOT NULL,
    state        text           NOT NULL DEFAULT 'open'
                                CHECK (state IN ('open', 'confirmed', 'rejected', 'running',
                                                 'done', 'partial')),
    decided_by   text,
    decided_at   timestamptz(3),
    changed_at   timestamptz(3),
    -- salt (16) + log_n (1) + scrypt key (32) of an export, from the confirmation until
    -- the run takes it; never the passphrase.
    archive_key  bytea          CHECK (archive_key IS NULL OR
                                       (operation = 'export' AND octet_length(archive_key) = 49)),
    CHECK (requested_by <> confirmed_by),
    CHECK ((state = 'open') = (decided_by IS NULL AND decided_at IS NULL)),
    CHECK (state IN ('open', 'rejected') OR decided_by = confirmed_by),
    CHECK (archive_key IS NULL OR state IN ('confirmed', 'running'))
);
CREATE INDEX person_request_requested_by ON audit.person_request (requested_by, requested_at);
CREATE INDEX person_request_confirmed_by ON audit.person_request (confirmed_by, requested_at);

CREATE TRIGGER person_request_no_delete BEFORE DELETE ON audit.person_request
    FOR EACH ROW EXECUTE FUNCTION audit.refuse_change();
CREATE TRIGGER person_request_no_truncate BEFORE TRUNCATE ON audit.person_request
    FOR EACH STATEMENT EXECUTE FUNCTION audit.refuse_change();

-- The event a function appends must be the one of its change: writer, event, acting
-- person and request id.
CREATE FUNCTION audit.person_request_event(p_canonical text, p_event text, p_sub text,
                                           p_id uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_body jsonb := p_canonical::jsonb;
BEGIN
    IF NOT (v_body ->> 'writer' = 'papaia-audit/person'
            AND v_body ->> 'event' = p_event
            AND v_body ->> 'result' = 'allowed'
            AND v_body ->> 'sub' = p_sub
            AND v_body -> 'object_ref' ->> 'type' = 'person_request'
            AND v_body -> 'object_ref' ->> 'id' = p_id::text)
    THEN
        RAISE EXCEPTION 'not the event of this request' USING ERRCODE = 'insufficient_privilege';
    END IF;
    PERFORM audit.append('papaia-audit', p_canonical);
END
$$;

CREATE FUNCTION audit.person_request_add(p_id uuid, p_operation text, p_sub text,
                                         p_transfer_to text, p_requested_by text,
                                         p_confirmed_by text, p_at timestamptz,
                                         p_canonical text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    INSERT INTO audit.person_request (id, operation, sub, transfer_to, requested_by,
                                      confirmed_by, requested_at)
    VALUES (p_id, p_operation, p_sub, p_transfer_to, p_requested_by, p_confirmed_by, p_at);
    PERFORM audit.person_request_event(p_canonical, 'person_request_created', p_requested_by,
                                       p_id);
END
$$;

-- Confirms (with the key of an export) or rejects an open request of the last 7 days by
-- the database clock. Only the named confirming person confirms, never the requesting
-- one; either of the two may reject. False and nothing changed when it is not open.
CREATE FUNCTION audit.person_request_decide(p_id uuid, p_state text, p_by text,
                                            p_at timestamptz, p_key bytea, p_canonical text)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_request audit.person_request%ROWTYPE;
BEGIN
    SELECT * INTO v_request FROM audit.person_request r
        WHERE r.id = p_id AND r.state = 'open' FOR UPDATE;
    IF NOT FOUND
       OR greatest(p_at, clock_timestamp()) >= v_request.requested_at + interval '7 days' THEN
        RETURN false;
    END IF;
    IF p_state = 'confirmed' THEN
        IF p_by <> v_request.confirmed_by OR p_by = v_request.requested_by THEN
            RAISE EXCEPTION 'a request is confirmed by the second person it names'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
        IF (p_key IS NOT NULL) <> (v_request.operation = 'export') THEN
            RAISE EXCEPTION 'an export, and only an export, carries an archive key'
                USING ERRCODE = 'check_violation';
        END IF;
    ELSIF p_state = 'rejected' THEN
        IF p_by NOT IN (v_request.confirmed_by, v_request.requested_by) OR p_key IS NOT NULL THEN
            RAISE EXCEPTION 'a request is rejected by one of its two persons'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
    ELSE
        RAISE EXCEPTION 'a request is confirmed or rejected' USING ERRCODE = 'check_violation';
    END IF;
    UPDATE audit.person_request
        SET state = p_state, decided_by = p_by, decided_at = p_at, archive_key = p_key
        WHERE id = p_id;
    PERFORM audit.person_request_event(p_canonical, 'person_request_' || p_state, p_by, p_id);
    RETURN true;
END
$$;

-- confirmed -> running within 24 hours of the confirmation, running -> done | partial
-- (dropping a key the run did not take). The event is the `operation` row of the run,
-- in the name of the requesting person.
CREATE FUNCTION audit.person_request_advance(p_id uuid, p_from text, p_to text,
                                             p_at timestamptz, p_canonical text)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_request audit.person_request%ROWTYPE;
BEGIN
    IF NOT ((p_from = 'confirmed' AND p_to = 'running')
            OR (p_from = 'running' AND p_to IN ('done', 'partial'))) THEN
        RAISE EXCEPTION 'not a step of a request' USING ERRCODE = 'check_violation';
    END IF;
    SELECT * INTO v_request FROM audit.person_request r
        WHERE r.id = p_id AND r.state = p_from FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    IF p_from = 'confirmed'
       AND greatest(p_at, clock_timestamp()) >= v_request.decided_at + interval '24 hours' THEN
        RETURN false;
    END IF;
    UPDATE audit.person_request
        SET state = p_to, changed_at = p_at,
            archive_key = CASE WHEN p_to = 'running' THEN archive_key END
        WHERE id = p_id;
    PERFORM audit.person_request_event(p_canonical, 'operation', v_request.requested_by, p_id);
    RETURN true;
END
$$;

-- The key of a running export, removed as it is read; NULL (and no event) when it is
-- gone.
CREATE FUNCTION audit.person_request_take_key(p_id uuid, p_canonical text) RETURNS bytea
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_request audit.person_request%ROWTYPE;
BEGIN
    SELECT * INTO v_request FROM audit.person_request r
        WHERE r.id = p_id AND r.state = 'running' AND r.archive_key IS NOT NULL FOR UPDATE;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    UPDATE audit.person_request SET archive_key = NULL WHERE id = p_id;
    PERFORM audit.person_request_event(p_canonical, 'operation', v_request.requested_by, p_id);
    RETURN v_request.archive_key;
END
$$;

REVOKE ALL ON FUNCTION audit.person_request_event(text, text, text, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.person_request_add(uuid, text, text, text, text, text,
                                                timestamptz, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.person_request_decide(uuid, text, text, timestamptz, bytea, text)
    FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.person_request_advance(uuid, text, text, timestamptz, text)
    FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.person_request_take_key(uuid, text) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION audit.person_request_add(uuid, text, text, text, text, text,
                                                   timestamptz, text) TO audit_hold;
GRANT EXECUTE ON FUNCTION audit.person_request_decide(uuid, text, text, timestamptz, bytea,
                                                      text) TO audit_hold;
GRANT EXECUTE ON FUNCTION audit.person_request_advance(uuid, text, text, timestamptz, text)
    TO audit_hold;
GRANT EXECUTE ON FUNCTION audit.person_request_take_key(uuid, text) TO audit_hold;
-- The read role sees the requests, never the key.
GRANT SELECT (id, operation, sub, transfer_to, requested_by, confirmed_by, requested_at, state,
              decided_by, decided_at, changed_at)
    ON audit.person_request TO audit_read;
