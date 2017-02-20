
BEGIN WORK;

CREATE TABLE IF NOT EXISTS users (
    user_id uuid NOT NULL primary key DEFAULT uuid_generate_v4(),
    user_name varchar(50) NOT NULL,
    full_name varchar(250),
    email varchar(250) NOT NULL,
    passwd varchar(250) NOT NULL,
    is_admin bool NOT NULL DEFAULT False,
    is_sticky bool NOT NULL DEFAULT False,
    max_hosts integer DEFAULT 3,
    disabled bool NOT NULL DEFAULT False,
    created timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    modified timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    description text,
    list_limit integer,
    CONSTRAINT unique_user_name UNIQUE(user_name)
);

COMMENT ON TABLE users IS 'All registered users of this application.';

COMMENT ON COLUMN users.user_id     IS 'A UUID of this user, used as a primary key.';
COMMENT ON COLUMN users.user_name   IS 'The login name of then current user, must be unique.';
COMMENT ON COLUMN users.full_name   IS 'The full name of the current user. Editable by the user itself.';
COMMENT ON COLUMN users.email       IS 'E-Mail-address of the current user.';
COMMENT ON COLUMN users.passwd      IS 'The SHA-512 salted hashed password of the current user.';
COMMENT ON COLUMN users.is_admin    IS 'Flag, whether the user is an administrator, or not.';
COMMENT ON COLUMN users.is_sticky   IS 'Flag, that the user may not be deleted or renamed.';
COMMENT ON COLUMN users.max_hosts   IS 'Number of maximum hosts a user may host with this application.';
COMMENT ON COLUMN users.disabled    IS 'Flag, whether the user is disabled or not.';
COMMENT ON COLUMN users.created     IS 'The timestamp of the creation of this user.';
COMMENT ON COLUMN users.modified    IS 'The timestamp of the last modification of this user.';
COMMENT ON COLUMN users.description IS 'Optional additional description of this user.';
COMMENT ON COLUMN users.list_limit  IS 'Limit in output of longer lists of objects. If NULL, the global list limit will be used.';

-- password: password
INSERT INTO users (
    user_name, full_name, email,
    passwd,
    is_admin, is_sticky, max_hosts, description, list_limit
)
VALUES (
    'admin', 'Administrator', 'webmaster@brehm-online.com',
    '$6$jQbHxAyrUw.c3M5g$CtaKH7BouFOPXLN.YL3zYpxB.sGi6WBUYKREsfHQ5fdJ99Wli6gGujtZgPADRcU0S0RvSCMh69iTY0SrAeeFD0',
    True, True, NULL, 'The default administrator of this application.', NULL
);

COMMIT;

\q

-- vim: ts=4 et
