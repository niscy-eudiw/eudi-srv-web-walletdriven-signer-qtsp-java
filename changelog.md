# Changelog

## [0.3.0]
_02 Dec 2024_

### Added:
- Error page to display errors in the OID4VP authentication process.
- Added support for the OID4VP cross-device flow

### Fixed
- Bug that introduced the possibility of skipping authentication.
- Remove parts of VP Token validation steps that will be updated later to support VP Token changes.
- Issue #11: 'Authentication Issues'

## [0.2.0]

_18 Nov 2024_

### Added:

- Endpoints based on the CSC 2.0 Specification ('credentials/list', 'credentials/info' and 'signatures/signHash').
- OAuth2.0 Authorization Endpoints for service and credential authorization.
- Authentication with OpenID for Verifiable Presentations.
- Validation of Verifiable Presentation Token.
- Authentication with Forms.
- Certificate issuance with EJBCA and ECDSA Keys Issuance with vHSM.
- Calculation of the signature of hashes.
- Support for a MySQL Database.