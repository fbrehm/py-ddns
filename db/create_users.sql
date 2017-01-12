
BEGIN WORK;

CREATE TABLE IF NOT EXISTS users (
    user_id uuid primary key DEFAULT uuid_generate_v4(),
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

-- eiPo4vo|i&ye
INSERT INTO users (
    user_name, full_name, email,
    passwd,
    is_admin, is_sticky, max_hosts, description
)
VALUES (
    'admin', 'Administrator', 'webmaster@brehm-online.com',
    '$6$HA8X/TJ0SY7$MYqi7oJG9CnJ/SllbjwRgnzheTaHRpUnlwidZPQYtxK6WCZ05VnksAkxdCg4FNG2r.Y5F1t5Bfcpl2zEdWeM31',
    True, True, NULL, 'The default administrator of tis application.'
);

INSERT INTO users (
    user_name, full_name, email,
    passwd,
    is_admin, is_sticky, max_hosts, description
)
VALUES (
    'frank', 'Frank Brehm', 'frank@brehm-online.com',
    '$6$cX.uoegn$QJ4gODV46s22yZL5568YNM/TqhlRqVOK42ulOijyMRZN4A049BLsbTB/M/8XO/rJwFs8w4sSS7mEPsdZtyzQI1',
    True, False, NULL, 'Ich höchstpersönlich.'
);

INSERT INTO users (
    user_name, full_name, email,
    passwd,
    is_admin, is_sticky, max_hosts, description
)
VALUES (
    'thomas', 'Thomas Schmidt', 'thomas@nexunus.net',
    '$6$2ZG/G/Rzm$XmlHtFmQrLjU7LnCoQBmeMkvFhMTY..9HbR8ttSlHGVpOmAhSxofJV8Q/ltZmv1dM1mTDn8xLzofyQAZ.UqWv0',
    True, False, NULL, 'Der andere.'
);

COMMIT;

\q

-- vim: ts=4 et
