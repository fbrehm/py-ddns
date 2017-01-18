
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
    CONSTRAINT unique_user_name UNIQUE(user_name)
);

-- password: password
INSERT INTO users (
    user_name, full_name, email,
    passwd,
    is_admin, is_sticky, max_hosts, description
)
VALUES (
    'admin', 'Administrator', 'webmaster@brehm-online.com',
    '$6$jQbHxAyrUw.c3M5g$CtaKH7BouFOPXLN.YL3zYpxB.sGi6WBUYKREsfHQ5fdJ99Wli6gGujtZgPADRcU0S0RvSCMh69iTY0SrAeeFD0',
    True, True, NULL, 'The default administrator of tis application.'
);

COMMIT;

\q

-- vim: ts=4 et
