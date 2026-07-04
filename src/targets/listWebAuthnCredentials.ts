import type { Services } from "../services";
import { resolveUserFromAccessToken } from "./accessTokenUser";
import type { Target } from "./Target";
import type {
  ListWebAuthnCredentialsRequest,
  ListWebAuthnCredentialsResponse,
} from "./webAuthnTypes";

export type ListWebAuthnCredentialsTarget = Target<
  ListWebAuthnCredentialsRequest,
  ListWebAuthnCredentialsResponse
>;

type ListWebAuthnCredentialsServices = Pick<Services, "cognito">;

/**
 * ListWebAuthnCredentials returns the passkeys registered for the caller. The
 * stored public-key blob is intentionally omitted from the response.
 */
export const ListWebAuthnCredentials =
  ({
    cognito,
  }: ListWebAuthnCredentialsServices): ListWebAuthnCredentialsTarget =>
  async (ctx, req) => {
    const { user } = await resolveUserFromAccessToken(
      ctx,
      cognito,
      req.AccessToken,
    );

    return {
      Credentials: (user.WebAuthnCredentials ?? []).map((credential) => ({
        CredentialId: credential.CredentialId,
        FriendlyCredentialName: credential.FriendlyCredentialName,
        RelyingPartyId: credential.RelyingPartyId,
        AuthenticatorAttachment: credential.AuthenticatorAttachment,
        CreatedAt: credential.CreatedAt,
      })),
    };
  };
