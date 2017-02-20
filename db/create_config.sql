
BEGIN WORK;

CREATE TYPE config_type AS ENUM (
    'bool', 'int', 'float', 'str', 'uuid', 'version',
    'date', 'time', 'time_tz', 'timestamp', 'timestamp_tz', 'time_diff'
);

COMMENT ON TYPE config_type IS 'All available configuration value types.';

CREATE TABLE IF NOT EXISTS config (
    cfg_name varchar(250) NOT NULL primary key,
    cfg_type config_type,
    cfg_value varchar(250),
    created timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    modified timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    description text
);

COMMENT ON TABLE config IS 'All global configuration options, available after establishing a database session.';

COMMENT ON COLUMN config.cfg_name    IS 'The name of the configuration option, used as a primary key.';
COMMENT ON COLUMN config.cfg_type    IS 'The data type of the value of the configuration option. Must be one of type config_type.';
COMMENT ON COLUMN config.cfg_value   IS 'The value of the configuration option.';
COMMENT ON COLUMN config.created     IS 'The timestamp of the creation of this particular configuration option.';
COMMENT ON COLUMN config.modified    IS 'The timestamp of the last modification of this particular configuration option.';
COMMENT ON COLUMN config.description IS 'Optional additional description of this configuration option.';

INSERT INTO config (cfg_name, cfg_type, cfg_value)
 VALUES ('model_version', 'version', '0.1.0')
 ON CONFLICT (cfg_name) DO UPDATE
    SET cfg_type = 'version', cfg_value = '0.1.0', modified=CURRENT_TIMESTAMP;

COMMIT;

\q

-- vim: ts=4 et
