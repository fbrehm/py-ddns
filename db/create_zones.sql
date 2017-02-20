
BEGIN WORK;

CREATE SEQUENCE IF NOT EXISTS seq_zone_id
    INCREMENT BY 1
    START WITH 1;

COMMENT ON SEQUENCE seq_key_id IS 'Used for autoincrementing zone_id of table "zones".';

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

COMMENT ON TABLE zones IS 'All available zones, for which host entries could be created.';

COMMENT ON COLUMN zones.zone_id          IS 'Numeric Id of the zone, used as a primary key.';
COMMENT ON COLUMN zones.zone_name        IS 'DNS name of the zone. Must be unique.';
COMMENT ON COLUMN zones.master_ns        IS 'The primary (master) DNS server for this zone, where the updates are sent to. If NULL, this information will be evaluated from the SOA of this zone.';
COMMENT ON COLUMN zones.key_id           IS 'The numeric Id of the TSIG key from table "tsig_keys", which is used on updating zone records.';
COMMENT ON COLUMN zones.max_hosts        IS 'Maximum number of allowed host entries in this zone. Unlimited, if NULL.';
COMMENT ON COLUMN zones.default_min_wait IS 'Default minimum time after last update of a host entry, until a host entry will be deleted.';
COMMENT ON COLUMN zones.disabled         IS 'Flag, whether the zone is disabled or not.';
COMMENT ON COLUMN zones.created          IS 'The timestamp of the creation of this zone.';
COMMENT ON COLUMN zones.modified         IS 'The timestamp of the last modification iof global properties of this zone.';
COMMENT ON COLUMN zones.description      IS 'Optional additional description of this zone.';


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

COMMENT ON VIEW v_zones IS 'All available zones ordered by zone_name. Joined from tables "zones" with "tsig_keys"';

COMMENT ON COLUMN v_zones.zone_id          IS 'Numeric Id of the zone, used as a primary key.';
COMMENT ON COLUMN v_zones.zone_name        IS 'DNS name of the zone. Must be unique.';
COMMENT ON COLUMN v_zones.master_ns        IS 'The primary (master) DNS server for this zone, where the updates are sent to. If NULL, this information will be evaluated from the SOA of this zone.';
COMMENT ON COLUMN v_zones.key_id           IS 'The numeric Id of the TSIG key from table "tsig_keys", which is used on updating zone records.';
COMMENT ON COLUMN v_zones.key_name         IS 'Name of the TSIG key, how used in the named.conf.';
COMMENT ON COLUMN v_zones.key_value        IS 'Value of the TSIG key, how used in the named.conf.';
COMMENT ON COLUMN v_zones.max_hosts        IS 'Maximum number of allowed host entries in this zone. Unlimited, if NULL.';
COMMENT ON COLUMN v_zones.default_min_wait IS 'Default minimum time after last update of a host entry, until a host entry will be deleted.';
COMMENT ON COLUMN v_zones.disabled         IS 'Flag, whether the zone is disabled or not.';
COMMENT ON COLUMN v_zones.created          IS 'The timestamp of the creation of this zone.';
COMMENT ON COLUMN v_zones.modified         IS 'The timestamp of the last modification iof global properties of this zone.';
COMMENT ON COLUMN v_zones.description      IS 'Optional additional description of this zone.';

COMMIT;

\q

-- vim: ts=4 et
