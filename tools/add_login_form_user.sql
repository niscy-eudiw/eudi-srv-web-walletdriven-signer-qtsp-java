USE {database_name};

CREATE TABLE IF NOT EXISTS users (
    id varchar(255) NOT NULL PRIMARY KEY,
    role varchar(255) NOT NULL,
    hash varchar(255) NOT NULL UNIQUE,
    issuing_country varchar(255) NOT NULL,
    issuance_authority varchar(255),
    password varchar(255)
);

INSERT INTO users (id, hash, issuance_authority, issuing_country, role, password) VALUES
(UUID(), TO_BASE64(UNHEX(SHA2('{family_name};{given_name};{birth_date};{issuing_country}', 256))) , {issuance_authority}, {issuing_country}, 'user', {password});