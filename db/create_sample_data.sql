
BEGIN WORK;

-- blabla
INSERT INTO users (
    user_name, full_name, email,
    passwd,
    is_admin, is_sticky, max_hosts, description
)
VALUES (
    'frank', 'Frank Brehm', 'frank@brehm-online.com',
    '$5$Z1yIznlyCUYxG$6j92inq.66TkhfUCf0gLqNHDgyXrlKOzsQ1fISeaS.D',
    True, False, NULL, 'Ich höchstpersönlich.'
);

-- qqqq
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

-- uhu
INSERT INTO users (
    user_name, full_name, email,
    passwd,
    is_admin, is_sticky, max_hosts, description
)
VALUES (
    'guest', 'Gast', 'nobody@nexunus.net',
    '$6$gZNaI3.a/t$fikdw22JjIyVwKcHbMKYRZxHRkavrFvtRZyyIIhqb.DBJj2aArjS4BD6/.bv565WkKh4CSVBX28S1yD963YVS/',
    False, False, 3, 'Gastnutzer ohne Rechte'
);

INSERT INTO tsig_keys (
    key_name, key_value, description
) VALUES (+
    'DYN_DNS_UPDATER', 'gi69Yjzo1OSPVQ/oTTgw+Q==', 'Update key on Helga'
);

INSERT INTO zones (
    zone_name, master_ns,
    key_id,
    max_hosts, default_min_wait,
    disabled, description
) VALUES (
    'dyn.uhu-banane.de', '85.214.134.152',
    (SELECT key_id FROM tsig_keys WHERE key_name = 'DYN_DNS_UPDATER'),
    10, '1 hours',
    False, 'Testing'
);

COMMIT;

\q

-- vim: ts=4 et
