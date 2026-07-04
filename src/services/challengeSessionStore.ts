import * as uuid from "uuid";

const TTL_MS = 15 * 60 * 1000;

/**
 * ChallengeSession holds the server-side state that must survive across the
 * multi-request MFA_SETUP challenge flow (InitiateAuth → AssociateSoftwareToken
 * → VerifySoftwareToken → RespondToAuthChallenge). Unlike the ad-hoc `Session`
 * UUIDs the other challenge types emit, an MFA_SETUP session is persisted here
 * and validated on each subsequent request.
 */
export interface ChallengeSession {
  userPoolId: string;
  clientId: string;
  username: string;
  challengeName: string;

  /**
   * The in-progress software-token secret, populated by AssociateSoftwareToken
   * when it is driven via a Session rather than an AccessToken.
   */
  secret?: string;

  /**
   * Set to true once VerifySoftwareToken has confirmed the user's TOTP code for
   * this session. RespondToAuthChallenge requires this before issuing tokens.
   */
  verified?: boolean;
}

interface Entry extends ChallengeSession {
  expiresAt: number;
}

/**
 * ChallengeSessionStore is an in-memory, TTL-bounded store keyed by an opaque
 * session id. It mirrors AuthorizationCodeStore's shape but is used for auth
 * challenge continuity rather than the OAuth2 code exchange.
 */
export class ChallengeSessionStore {
  private readonly sessions = new Map<string, Entry>();

  /**
   * create stores a new challenge session and returns its opaque id.
   */
  create(data: ChallengeSession): string {
    const id = uuid.v4();
    this.sessions.set(id, { ...data, expiresAt: Date.now() + TTL_MS });
    return id;
  }

  /**
   * get returns the live session for the id, or null when it is missing or
   * expired. Expired sessions are evicted on access.
   */
  get(id: string): ChallengeSession | null {
    const entry = this.sessions.get(id);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      this.sessions.delete(id);
      return null;
    }
    const { expiresAt: _expiresAt, ...data } = entry;
    return data;
  }

  /**
   * update merges partial changes into a live session, preserving its
   * expiry. It is a no-op when the session is missing or expired.
   */
  update(id: string, updates: Partial<ChallengeSession>): void {
    const entry = this.sessions.get(id);
    if (!entry) return;
    if (Date.now() > entry.expiresAt) {
      this.sessions.delete(id);
      return;
    }
    this.sessions.set(id, { ...entry, ...updates });
  }

  /**
   * delete removes a session, used once the challenge flow completes.
   */
  delete(id: string): void {
    this.sessions.delete(id);
  }
}
