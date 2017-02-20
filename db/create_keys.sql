
BEGIN WORK;

CREATE SEQUENCE IF NOT EXISTS seq_key_id
    INCREMENT BY 1
    START WITH 1;

COMMENT ON SEQUENCE seq_key_id IS 'Used for autoincrementing key_id of table tsig_keys.';

CREATE TABLE IF NOT EXISTS tsig_keys (
    key_id integer NOT NULL primary key DEFAULT nextval('seq_key_id'),
    key_name varchar(250) NOT NULL,
    key_value varchar(250) NOT NULL,
    disabled bool NOT NULL DEFAULT False,
    created timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    description text,
    CONSTRAINT unique_key_name UNIQUE(key_name)
);

COMMENT ON TABLE tsig_keys IS 'All available TSIG keys for updating zones.';

COMMENT ON COLUMN tsig_keys.key_id      IS 'Numeric Id of the TSIG key, used as a primary key.';
COMMENT ON COLUMN tsig_keys.key_name    IS 'Name of the TSIG key, how used in the named.conf.';
COMMENT ON COLUMN tsig_keys.key_value   IS 'Value of the TSIG key, how used in the named.conf.';
COMMENT ON COLUMN tsig_keys.disabled    IS 'Flag, whether the TSIG key is enabled and usable, or not.';
COMMENT ON COLUMN tsig_keys.created     IS 'The timestamp of the creation of this particular TSIG key.';
COMMENT ON COLUMN tsig_keys.description IS 'Optional additional description of the particular TSIG key.';

COMMIT;

\q

-- vim: ts=4 et
