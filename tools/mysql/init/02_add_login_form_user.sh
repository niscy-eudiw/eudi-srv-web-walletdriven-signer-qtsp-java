#!/bin/bash
set -e
# Skip if no test user is configured
[[ -z "$LOGIN_USER_GIVEN_NAME" ]] && exit 0

mysql -uroot -p"$MYSQL_ROOT_PASSWORD" "$MYSQL_DATABASE" <<EOSQL


CREATE TABLE IF NOT EXISTS users (
    id varchar(255) NOT NULL PRIMARY KEY,
    role varchar(255) NOT NULL,
    hash varchar(255) NOT NULL UNIQUE,
    issuing_country varchar(255) NOT NULL,
    issuance_authority varchar(255),
    password varchar(255)
);

INSERT INTO users (id, hash, issuance_authority, issuing_country, role, password) VALUES
(UUID(), TO_BASE64(UNHEX(SHA2('${LOGIN_USER_FAMILY_NAME};${LOGIN_USER_GIVEN_NAME};${LOGIN_USER_BIRTH_DATE};${LOGIN_USER_ISSUING_COUNTRY}', 256))),
 '${LOGIN_USER_ISSUANCE_AUTHORITY}', '${LOGIN_USER_ISSUING_COUNTRY}', 'user', '${LOGIN_USER_PASSWORD}');
EOSQL