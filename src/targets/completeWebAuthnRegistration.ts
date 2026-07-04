import { randomBytes } from "node:crypto";
import type { Services } from "../services";
import type { WebAuthnCredential } from "../services/userPoolService";
import { resolveUserFromAccessToken } from "./accessTokenUser";
import type { Target } from "./Target";
import type {
  CompleteWebAuthnRegistrationRequest,
  CompleteWebAuthnRegistrationResponse,
} from "./webAuthnTypes";

export type CompleteWebAuthnRegistrationTarget = Target<
  CompleteWebAuthnRegistrationRequest,
  CompleteWebAuthnRegistrationResponse
>;

type CompleteWebAuthnRegistrationServices = Pick<Services, "clock" | "cognito">;

const stringField = (
  doc: Record<string, unknown>,
  key: string,
): string | undefined => (typeof doc[key] === "string" ? doc[key] : undefined);

/**
 * CompleteWebAuthnRegistration persists the passkey produced by the client. The
 * attestation is stored verbatim but not cryptographically verified.
 */
export const CompleteWebAuthnRegistration =
  ({
    clock,
    cognito,
  }: CompleteWebAuthnRegistrationServices): CompleteWebAuthnRegistrationTarget =>
  async (ctx, req) => {
    const { userPool, user } = await resolveUserFromAccessToken(
      ctx,
      cognito,
      req.AccessToken,
    );

    const credential = req.Credential ?? {};
    const credentialId =
      stringField(credential, "id") ??
      stringField(credential, "rawId") ??
      randomBytes(16).toString("base64url");

    const newCredential: WebAuthnCredential = {
      CredentialId: credentialId,
      FriendlyCredentialName: stringField(credential, "friendlyName"),
      RelyingPartyId: "localhost",
      AuthenticatorAttachment: stringField(
        credential,
        "authenticatorAttachment",
      ),
      CreatedAt: clock.get(),
      PublicKey: JSON.stringify(credential),
    };

    await userPool.saveUser(ctx, {
      ...user,
      WebAuthnCredentials: [...(user.WebAuthnCredentials ?? []), newCredential],
    });

    return {};
  };
