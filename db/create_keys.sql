
BEGIN WORK;

CREATE SEQUENCE IF NOT EXISTS seq_key_id
    INCREMENT BY 1
    START WITH 1;

CREATE TABLE IF NOT EXISTS tsig_keys (
    key_id integer NOT NULL primary key DEFAULT nextval('seq_key_id'),
    key_name varchar(250) NOT NULL,
    key_value varchar(250) NOT NULL,
    disabled bool NOT NULL DEFAULT False,
    created timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    description text
);

COMMIT;

\q

-- vim: ts=4 et
