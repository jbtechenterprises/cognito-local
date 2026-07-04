import { randomBytes } from "node:crypto";
import type { Services } from "../services";
import { attributeValue } from "../services/userPoolService";
import { resolveUserFromAccessToken } from "./accessTokenUser";
import type { Target } from "./Target";
import type {
  StartWebAuthnRegistrationRequest,
  StartWebAuthnRegistrationResponse,
} from "./webAuthnTypes";

export type StartWebAuthnRegistrationTarget = Target<
  StartWebAuthnRegistrationRequest,
  StartWebAuthnRegistrationResponse
>;

type StartWebAuthnRegistrationServices = Pick<Services, "cognito">;

/**
 * StartWebAuthnRegistration begins passkey registration by returning
 * WebAuthn CredentialCreationOptions with a fresh challenge. cognito-local does
 * not verify the resulting attestation, so the challenge is informational only.
 */
export const StartWebAuthnRegistration =
  ({
    cognito,
  }: StartWebAuthnRegistrationServices): StartWebAuthnRegistrationTarget =>
  async (ctx, req) => {
    const { user } = await resolveUserFromAccessToken(
      ctx,
      cognito,
      req.AccessToken,
    );

    const challenge = randomBytes(32).toString("base64url");
    const userId = attributeValue("sub", user.Attributes) ?? user.Username;

    return {
      CredentialCreationOptions: {
        challenge,
        rp: { name: "Cognito Local", id: "localhost" },
        user: {
          id: Buffer.from(userId).toString("base64url"),
          name: user.Username,
          displayName: user.Username,
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 },
        ],
        timeout: 60000,
        attestation: "none",
        authenticatorSelection: { userVerification: "preferred" },
      },
    };
  };
