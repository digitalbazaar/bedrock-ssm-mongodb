# bedrock-ssm-mongodb ChangeLog

## 11.0.0 - 2024-mm-dd

### Changed
- **BREAKING**: Do not use webkms-context in symmetric key descriptions
  as it is unnecessary. This should not cause breaks with systems that
  are integrated with this module (or clients that make use of it
  indirectly), but it is considered a breaking change to help prevent
  unforeseen incompatibilities.

## 10.1.3 - 2023-04-20

### Fixed
- DRY-up code having to do with keys and key operations.

## 10.1.2 - 2023-04-14

### Fixed
- Fix key description type to `Multikey` for key types that start with
  `urn:webkms:multikey:` in `getKeyDescription()`.
- Fix overwriting key type in `sign()`.

## 10.1.1 - 2023-03-30

### Changed
- Remove `lib/ecdsa` and use `@digitalbazaar/ecdsa-multikey@v1.1.1`.

### Fixed
- Fix multikey context url to `https://w3id.org/security/multikey/v1`.

## 10.1.0 - 2022-07-10

### Added
- Add support for ECDSA keys: P-256, P-384, P-521.

## 10.0.0 - 2022-06-30

### Changed
- **BREAKING**: Require Node.js >=16.
- Update dependencies.
- Lint module.
- Use `package.json` `files` field.

## 9.0.0 - 2022-04-29

### Changed
- **BREAKING**: Update peer deps:
  - `@bedrock/core@6`
  - `@bedrock/mongodb@10`
  - `@bedrock/package-manager@3`.

## 8.0.2 - 2022-04-09

### Fixed
- Use `require` to load lru-cache as some `esm.js` libraries
  also load it and can cause conflicts.

## 8.0.1 - 2022-04-05

### Fixed
- Fix package name registered with bedrock-package-manager.

## 8.0.0 - 2022-04-05

### Changed
- **BREAKING**: Rename package to `@bedrock/ssm-mongodb`.
- **BREAKING**: Convert to module (ESM).
- **BREAKING**: Remove default export.
- **BREAKING**: Require node 14.x.

## 7.2.0 - 2022-03-29

### Changed
- Update peer deps:
  - `bedrock@4.5`
  - `bedrock-mongodb@8.5`
  - `bedrock-package-manager@1.2`.
- Update internals to use esm style and use `esm.js` to
  transpile to CommonJS.

## 7.1.0 - 2022-01-14

### Added
- Support setting `maxCapabilityChainLength` during key generation.

## 7.0.1 - 2022-01-11

### Fixed
- Fix webkms context dependency.
- Update peer deps.

## 7.0.0 - 2022-01-11

### Changed
- **BREAKING**: Override `id` in public key description if `publicAlias` is
  set on key.
- **BREAKING**: Allow a public alias to be set on a key. During
  `generateKey()`, a `publicAlias` or a `publicAliasTemplate`
  may be passed to create a key. If not provided, then a future update to
  this module may allow a `publicAlias` or `publicAliasTemplate` to be
  be provided via an `UpdateKeyOperation` that includes a `publicAlias` or
  `publicAliasTemplate` value for the key.
- **BREAKING**: Require `controller` to be passed when generating a key or
  getting a key description.
- **BREAKING**: Return `{keyId, keyDescription}` from `generateKey`.

## 6.1.0 - 2021-12-14

### Changed
- Expose helper functions in order to properly test them.

## 6.0.2 - 2021-09-01

### Fixed
- Strip multicodec header from webkms local ID. Previous 6.x
  versions were broken and this fixes that bug.

## 6.0.1 - 2021-08-18

### Fixed
- Ensure `@context` is present on key agreement public keys.

## 6.0.0 - 2021-07-22

### Added
- Add `getKeyDescription` API.
- Add `getKeyCount` API.

### Changed
- **BREAKING**: Store `@context` with keys.
- **BREAKING**: Key records are indexed by both keystore ID and local ID
  with the format: `keyId == <keystoreId>/<localId>`. Databases must be
  dropped to upgrade to the new format.

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
