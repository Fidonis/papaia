-- papaia-audit read API (docs/audit.md, "Reading"). `python -m papaia_audit schema` runs
-- it once, in the same transaction as schema.sql, as the database owner, when the table
-- audit.person_query does not exist yet (a new store, or a store of an earlier release).
--
-- A person query is a request to see one person's events by name: who asked, for whom,
-- for which period and why, and who decided. The reason is free text, which an event of
-- papaia.audit/1 never carries; the events name the query by its id. Rows are added and
-- decided only through the functions below; nobody confirms their own request.

CREATE TABLE audit.person_query (
    id           uuid           PRIMARY KEY,
    requested_by text           NOT NULL,
    person_sub   text           NOT NULL,
    period_from  timestamptz(3) NOT NULL,
    period_to    timestamptz(3) NOT NULL,
    reason       text           NOT NULL CHECK (char_length(reason) BETWEEN 20 AND 1000),
    requested_at timestamptz(3) NOT NULL,
    state        text           NOT NULL DEFAULT 'open'
                                CHECK (state IN ('open', 'confirmed', 'rejected')),
    decided_by   text,
    decided_at   timestamptz(3),
    CHECK (period_from < period_to AND period_to - period_from <= interval '93 days'),
    CHECK ((state = 'open') = (decided_by IS NULL AND decided_at IS NULL)),
    CHECK (state <> 'confirmed' OR decided_by <> requested_by)
);

CREATE INDEX person_query_open ON audit.person_query (requested_at) WHERE state = 'open';
CREATE INDEX person_query_person ON audit.person_query (person_sub);

CREATE TRIGGER person_query_no_delete BEFORE DELETE ON audit.person_query
    FOR EACH ROW EXECUTE FUNCTION audit.refuse_change();
CREATE TRIGGER person_query_no_truncate BEFORE TRUNCATE ON audit.person_query
    FOR EACH STATEMENT EXECUTE FUNCTION audit.refuse_change();

CREATE FUNCTION audit.person_query_add(p_id uuid, p_requested_by text, p_person_sub text,
                                       p_from timestamptz, p_to timestamptz, p_reason text,
                                       p_at timestamptz) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    INSERT INTO audit.person_query (id, requested_by, person_sub, period_from, period_to,
                                    reason, requested_at)
    VALUES (p_id, p_requested_by, p_person_sub, p_from, p_to, p_reason, p_at);
$$;

-- Closes an open query; false when it is no longer open. The table's check refuses a
-- confirmation by the requester.
CREATE FUNCTION audit.person_query_decide(p_id uuid, p_state text, p_by text,
                                          p_at timestamptz) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF p_state NOT IN ('confirmed', 'rejected') THEN
        RAISE EXCEPTION 'invalid state' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    UPDATE audit.person_query SET state = p_state, decided_by = p_by, decided_at = p_at
        WHERE id = p_id AND state = 'open';
    RETURN FOUND;
END
$$;

-- The next source_seq of a source, under the same per-source lock as audit.append, which
-- the caller runs in the same transaction: papaia-audit writes its own events with it.
CREATE FUNCTION audit.next_source_seq(p_source text) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext(p_source));
    RETURN coalesce((SELECT max(e.source_seq) FROM audit.event e
                     WHERE e.source = p_source), 0) + 1;
END
$$;

REVOKE ALL ON FUNCTION audit.person_query_add(uuid, text, text, timestamptz, timestamptz,
                                              text, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.person_query_decide(uuid, text, text, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.next_source_seq(text) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION audit.person_query_add(uuid, text, text, timestamptz, timestamptz,
                                                 text, timestamptz) TO audit_ingest;
GRANT EXECUTE ON FUNCTION audit.person_query_decide(uuid, text, text, timestamptz)
    TO audit_ingest;
GRANT EXECUTE ON FUNCTION audit.next_source_seq(text) TO audit_ingest;
GRANT SELECT ON audit.person_query TO audit_read;
