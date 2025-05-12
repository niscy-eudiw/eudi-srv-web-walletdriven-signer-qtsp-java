# Changelog

## [0.3.0]
_09 May 2025_

### Added:
- Error page to display issues encountered during the OID4VP authentication process.
- Support for the OID4VP cross-device authentication flow.

### Changed:
- Update Maven dependencies and remove unused javascript/CSS libraries.
- Refactored how required OID4VP authentication local variables are managed.
- Updated OAuth 2.0 client registration and logic to determine whether cross-device or same-device authentication applies.

### Fixed
- Resolved bug that allowed authentication to be bypassed.
- Fixed an issue caused by unexpected expiration of client_secrets.
- Issue #11 - 'Authentication Issues'
- Issue #13 - 'Update VP Token Validation Library': replaced the local VP Token validation mechanism with a call to the OID4VP Verifier Endpoint.
- Issue #17 - 'Update the oauth2/token to follow CSC'
- Issue #19 - 'HSM SecretKey Template Properties'

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