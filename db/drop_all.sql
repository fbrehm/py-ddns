
BEGIN WORK;


DROP TABLE IF EXISTS users;

DROP TABLE IF EXISTS tsig_keys;
DROP SEQUENCE IF EXISTS seq_key_id;

COMMIT;

\q

-- vim: ts=4 et
