-- papaia-audit store (docs/audit.md). `python -m papaia_audit schema` runs it once, in
-- one transaction, as the database owner, when the schema audit does not exist yet.
--
-- One hash chain per source: hash = SHA-256(prev_hash || canonical body), the first
-- event of a source links to 32 zero bytes. Only audit.append writes; triggers refuse
-- every UPDATE, DELETE and TRUNCATE. The service logs in as audit_ingest (may only call
-- audit.append) or audit_read (may only read); neither may change a row.

REVOKE ALL ON DATABASE audit FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;

CREATE SCHEMA audit;

CREATE TABLE audit.event (
    source         text           NOT NULL,
    seq            bigint         NOT NULL CHECK (seq >= 1),
    source_seq     bigint         NOT NULL CHECK (source_seq >= 1),
    time           timestamptz(3) NOT NULL,
    received_at    timestamptz(3) NOT NULL DEFAULT clock_timestamp(),
    prev_hash      bytea          NOT NULL CHECK (octet_length(prev_hash) = 32),
    hash           bytea          NOT NULL CHECK (octet_length(hash) = 32),
    sub            text,
    event          text           NOT NULL,
    correlation_id text           NOT NULL,
    catalog_id     text,
    result         text           NOT NULL,
    body           jsonb          NOT NULL,
    PRIMARY KEY (source, seq),
    UNIQUE (source, source_seq)
);

CREATE INDEX event_correlation_id ON audit.event (correlation_id);
CREATE INDEX event_event_time ON audit.event (event, time);
CREATE INDEX event_catalog_id_time ON audit.event (catalog_id, time);

CREATE FUNCTION audit.refuse_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit events cannot be changed or removed'
        USING ERRCODE = 'insufficient_privilege';
END
$$;

CREATE TRIGGER event_append_only BEFORE UPDATE OR DELETE ON audit.event
    FOR EACH ROW EXECUTE FUNCTION audit.refuse_change();
CREATE TRIGGER event_no_truncate BEFORE TRUNCATE ON audit.event
    FOR EACH STATEMENT EXECUTE FUNCTION audit.refuse_change();

-- Stores one canonical event of a source and returns its seq. A source_seq that is
-- already stored returns the seq it has (a repeated delivery); any other source_seq
-- than the next one raises SQLSTATE PA001 and stores nothing.
CREATE FUNCTION audit.append(p_source text, p_canonical text) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_body       jsonb := p_canonical::jsonb;
    v_source_seq bigint := (v_body ->> 'source_seq')::bigint;
    v_seq        bigint;
    v_last_seq   bigint;
    v_last_ss    bigint;
    v_prev       bytea;
BEGIN
    IF p_source !~ '^[a-z][a-z0-9-]{0,62}$' OR v_source_seq IS NULL THEN
        RAISE EXCEPTION 'invalid source or source_seq' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- One writer per source at a time; the chain is extended in order.
    PERFORM pg_advisory_xact_lock(hashtext(p_source));

    SELECT e.seq INTO v_seq FROM audit.event e
        WHERE e.source = p_source AND e.source_seq = v_source_seq;
    IF FOUND THEN
        RETURN v_seq;
    END IF;

    SELECT e.seq, e.source_seq, e.hash INTO v_last_seq, v_last_ss, v_prev FROM audit.event e
        WHERE e.source = p_source ORDER BY e.seq DESC LIMIT 1;
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

REVOKE ALL ON FUNCTION audit.append(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.refuse_change() FROM PUBLIC;

CREATE ROLE audit_ingest LOGIN;
CREATE ROLE audit_read LOGIN;
GRANT CONNECT ON DATABASE audit TO audit_ingest, audit_read;
GRANT USAGE ON SCHEMA audit TO audit_ingest, audit_read;
GRANT EXECUTE ON FUNCTION audit.append(text, text) TO audit_ingest;
GRANT SELECT ON audit.event TO audit_read;
