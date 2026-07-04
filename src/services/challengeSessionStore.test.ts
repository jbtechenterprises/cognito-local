import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ChallengeSessionStore } from "./challengeSessionStore";

describe("ChallengeSessionStore", () => {
  let store: ChallengeSessionStore;

  const baseSession = {
    userPoolId: "pool",
    clientId: "client",
    username: "user",
    challengeName: "MFA_SETUP",
  };

  beforeEach(() => {
    vi.useFakeTimers();
    store = new ChallengeSessionStore();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("stores and retrieves a session by its returned id", () => {
    const id = store.create(baseSession);

    expect(store.get(id)).toEqual(baseSession);
  });

  it("returns null for an unknown session", () => {
    expect(store.get("nope")).toBeNull();
  });

  it("expires sessions after the TTL", () => {
    const id = store.create(baseSession);

    vi.advanceTimersByTime(15 * 60 * 1000 + 1);

    expect(store.get(id)).toBeNull();
  });

  it("merges updates into a live session", () => {
    const id = store.create(baseSession);

    store.update(id, { secret: "s", verified: true });

    expect(store.get(id)).toEqual({
      ...baseSession,
      secret: "s",
      verified: true,
    });
  });

  it("ignores updates to a missing session", () => {
    expect(() => store.update("nope", { verified: true })).not.toThrow();
  });

  it("deletes a session", () => {
    const id = store.create(baseSession);

    store.delete(id);

    expect(store.get(id)).toBeNull();
  });
});
