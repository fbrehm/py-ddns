
BEGIN WORK;

CREATE SEQUENCE IF NOT EXISTS seq_zone_id
    INCREMENT BY 1
    START WITH 1;

CREATE TABLE IF NOT EXISTS zones (
    zone_id integer NOT NULL primary key DEFAULT nextval('seq_zone_id'),
    zone_name varchar(250) NOT NULL,
    master_ns varchar(250),
    key_id integer NOT NULL REFERENCES tsig_keys (key_id) ON DELETE RESTRICT,
    max_hosts integer,
    default_min_wait interval(0),
    disabled bool NOT NULL DEFAULT False,
    created timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    modified timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    description text,
    CONSTRAINT unique_zone_name UNIQUE(zone_name)
);

COMMIT;

\q

-- vim: ts=4 et
