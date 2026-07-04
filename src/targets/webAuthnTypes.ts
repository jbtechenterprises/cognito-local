/**
 * Hand-authored WebAuthn (passkey) request/response types.
 *
 * The bundled aws-sdk v2 predates Cognito's WebAuthn API, so these operations
 * have no generated types. These interfaces mirror the current AWS Cognito
 * WebAuthn API shape closely enough for local dev and integration tests.
 *
 * LIMITATION — emulation only, not a security boundary:
 * cognito-local reproduces the WebAuthn *flow and data shape* but performs no
 * FIDO2 cryptography. On registration the attestation object is stored verbatim
 * and never verified; the registration challenge is informational only. On the
 * assertion (sign-in) side, signatures, challenge binding, and the authenticator
 * signature counter are likewise not checked. This is deliberate and consistent
 * with the rest of the emulator (plaintext passwords, unverified challenge
 * sessions, a throwaway signing key) — it is sufficient for developing and
 * testing a client's Cognito integration locally, but must never be relied on
 * as real passkey security. See docs/webauthn-emulation.md.
 */

/** An arbitrary JSON document (WebAuthn options / credential blobs). */
export type WebAuthnDocument = Record<string, unknown>;

export interface StartWebAuthnRegistrationRequest {
  AccessToken: string;
}

export interface StartWebAuthnRegistrationResponse {
  CredentialCreationOptions: WebAuthnDocument;
}

export interface CompleteWebAuthnRegistrationRequest {
  AccessToken: string;
  Credential: WebAuthnDocument;
}

export type CompleteWebAuthnRegistrationResponse = Record<string, never>;

export interface WebAuthnCredentialDescription {
  CredentialId: string;
  FriendlyCredentialName?: string;
  RelyingPartyId?: string;
  AuthenticatorAttachment?: string;
  CreatedAt: Date;
}

export interface ListWebAuthnCredentialsRequest {
  AccessToken: string;
  MaxResults?: number;
  NextToken?: string;
}

export interface ListWebAuthnCredentialsResponse {
  Credentials: WebAuthnCredentialDescription[];
  NextToken?: string;
}

export interface DeleteWebAuthnCredentialRequest {
  AccessToken: string;
  CredentialId: string;
}

export type DeleteWebAuthnCredentialResponse = Record<string, never>;
