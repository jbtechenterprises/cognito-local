# WebAuthn (passkey) emulation

cognito-local implements the AWS Cognito WebAuthn operations
(`StartWebAuthnRegistration`, `CompleteWebAuthnRegistration`,
`ListWebAuthnCredentials`, `DeleteWebAuthnCredential`) so that clients can
exercise the passkey flow end-to-end against the local emulator.

## What is emulated

- **Registration start** returns real `CredentialCreationOptions` with a fresh
  32-byte challenge, relying-party info, and `pubKeyCredParams`.
- **Registration complete** persists the returned credential
  (`CredentialId`, friendly name, authenticator attachment, and the raw
  credential blob) on the user record (`user.WebAuthnCredentials`).
- **List / delete** operate on those stored credentials.

This matches the *flow and data shape* an integrating client observes from real
Cognito.

## What is NOT done (deliberate)

cognito-local performs **no FIDO2 cryptography**:

- The registration **attestation object is stored verbatim and never verified**;
  the registration challenge is informational only.
- On the assertion (sign-in) side, the **assertion signature, challenge
  binding, and authenticator signature counter are not checked**.

## Why this is sufficient for local dev

This is consistent with the rest of the emulator, which intentionally fakes
security primitives: passwords are compared in plaintext, the auth-challenge
`Session` is not cryptographically bound, and JWTs are signed with a bundled
throwaway key. cognito-local is a **local development and integration-test
tool, not a security boundary**. Real attestation/assertion verification would
protect against forged authenticators — a threat that does not exist on a
developer's machine — while adding a substantial CBOR/COSE/attestation-format
dependency surface that local tests cannot meaningfully assert against anyway.
Because Cognito verifies attestation server-side and only returns
success/failure to the client, emulating success gives a client integration the
same observable contract.

## When to revisit

Consider adding verification only if you specifically need to:

- Test **rejection paths** (invalid attestation, wrong RP ID, challenge
  mismatch, signature-counter regression) with realistic failures, or
- Validate a **real signature over the challenge** on passkey sign-in.

If so, the pragmatic middle ground is not full attestation verification but
lightweight **challenge binding + signature-counter checks** (e.g. via
`@simplewebauthn/server`), which catch the interesting bugs without reproducing
the full attestation-format matrix.
