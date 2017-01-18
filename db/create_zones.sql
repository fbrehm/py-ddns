
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

CREATE VIEW v_zones AS
SELECT z.zone_id            AS zone_id,
       z.zone_name          AS zone_name,
       z.master_ns          AS master_ns,
       z.key_id             AS key_id,
       k.key_name           AS key_name,
       k.key_value          AS key_value,
       z.max_hosts          AS max_hosts,
       z.default_min_wait   AS default_min_wait,
       z.disabled           AS disabled,
       z.created            AS created,
       z.modified           AS modified,
       z.description        AS description
FROM zones AS z
JOIN tsig_keys AS k ON z.key_id = k.key_id
ORDER BY z.zone_name;

COMMIT;

\q

-- vim: ts=4 et
