
BEGIN WORK;

CREATE TYPE config_type AS ENUM (
    'bool', 'int', 'float', 'str', 'uuid', 'version',
    'date', 'date_tz', 'time', 'timestamp', 'timestamp_tz', 'time_diff'
);

CREATE TABLE IF NOT EXISTS config (
    cfg_name varchar(250) NOT NULL primary key,
    cfg_type config_type,
    cfg_value varchar(250),
    created timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    modified timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    description text
);

INSERT INTO config (cfg_name, cfg_type, cfg_value)
 VALUES ('model_version', 'version', '0.1.0')
 ON CONFLICT (cfg_name) DO UPDATE
    SET cfg_type = 'version', cfg_value = '0.1.0', modified=CURRENT_TIMESTAMP;

COMMIT;

\q

-- vim: ts=4 et
