# bedrock-ssm-mongodb ChangeLog

## 6.0.0 - 2021-05-xx

### Added
- Add `getKeyDescription` API.

### Changed
- **BREAKING**: Store `@context` with keys.

## 5.0.0 - 2021-04-26

### Changed
- **BREAKING**: Use `webkms-context` url instead of security context v2.
- **BREAKING**: Replace X25519KeyAgreementKey2019 with X25519KeyAgreementKey2020
  suite for key agreement operations.
- **BREAKING**: Replace the local derived secret (based on scalarMult) with
  the X25519KeyAgreementKey2020 key pair's own `deriveSecret()`.
- Use [`aes-key-wrapping-2019-context@1.0.3`](https://github.com/digitalbazaar/aes-key-wrapping-2019-context/blob/main/CHANGELOG.md).
- Use [`sha256-hmac-key-2019-context@1.0.3`](https://github.com/digitalbazaar/sha256-hmac-key-2019-context/blob/main/CHANGELOG.md).
## 4.0.0 - 2021-04-08

### Changed
- **BREAKING**: Remove support for node 10.

### Added
- Add `Ed25519VerificationKey2020` to asymmetric key types.

## 3.2.1 - 2020-09-25

### Fixed
- Add and apply max age for cache for key records. Without
  this fix the cache can hold key records indefinitely even
  when they are changed by other processes.

## 3.2.0 - 2020-09-22

### Added
- Add cache for key records.

## 3.1.0 - 2020-07-07

### Changed
- Update peer deps, test deps and CI workflow.

### Fixed
- Fix usage of the MongoDB projection API.

## 3.0.0 - 2020-06-09

### Changed
  - **BREAKING**: Upgrade to `bedrock-mongodb` ^7.0.0.
  - Changed api calls from `insert` to `insertOne`.
  - Update test dependencies to `bedrock-mongodb: ^7.0.0.

## 2.0.1 - 2020-01-22

### Fixed
- Fix semver tag in package file for `bedrock` module.

## 2.0.0 - 2019-12-20

### Changed
- **BREAKING**: Update for use with webkms-switch v1.

### Added
- Add support for key agreement keys (e.g., X25519KeyAgreementKey).

## 1.0.0 - 2019-04-16

- See git history for changes.
