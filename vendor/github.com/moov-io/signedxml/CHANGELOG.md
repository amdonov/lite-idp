## v1.2.0 (Released 2024-02-19)

ADDITIONS

- signer: add convenience method for creating a signer given an already built etree.Document

IMPROVEMENTS

- fix: support Signature element on the root level

BUILD

- build: use latest stable Go release
- fix(deps): update module github.com/beevik/etree to v1.3.0
- fix(deps): update module github.com/smartystreets/goconvey to v1.8.1

## v1.1.1 (Released 2023-06-08)

IMPROVEMENTS

- Preserve CDATA text when signing a document
- Typo in TestEnvelopedSignatureProcess

## v1.1.0 (Released 2023-05-30)

IMPROVEMENTS

- feat: replace Validate() with ValidateReferences()
- meta: use moov-io/infra Go linter script in CI

## v1.0.0 (Released 2023-04-21)

This is the first tagged release of the `moov-io/signedxml` package. It was previously released `ma314smith/signedxml` but has been moved over to the Moov.io Github organization.
