import { InvalidParameterError } from "../errors";
import type { Services } from "../services";
import { resolveUserFromAccessToken } from "./accessTokenUser";
import type { Target } from "./Target";
import type {
  DeleteWebAuthnCredentialRequest,
  DeleteWebAuthnCredentialResponse,
} from "./webAuthnTypes";

export type DeleteWebAuthnCredentialTarget = Target<
  DeleteWebAuthnCredentialRequest,
  DeleteWebAuthnCredentialResponse
>;

type DeleteWebAuthnCredentialServices = Pick<Services, "cognito">;

/**
 * DeleteWebAuthnCredential removes a registered passkey by its credential id.
 */
export const DeleteWebAuthnCredential =
  ({
    cognito,
  }: DeleteWebAuthnCredentialServices): DeleteWebAuthnCredentialTarget =>
  async (ctx, req) => {
    if (!req.CredentialId) {
      throw new InvalidParameterError(
        "Missing required parameter CredentialId",
      );
    }

    const { userPool, user } = await resolveUserFromAccessToken(
      ctx,
      cognito,
      req.AccessToken,
    );

    await userPool.saveUser(ctx, {
      ...user,
      WebAuthnCredentials: (user.WebAuthnCredentials ?? []).filter(
        (credential) => credential.CredentialId !== req.CredentialId,
      ),
    });

    return {};
  };
