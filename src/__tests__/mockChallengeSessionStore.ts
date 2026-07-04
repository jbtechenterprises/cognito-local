import { type MockedObject, vi } from "vitest";
import type { ChallengeSessionStore } from "../services/challengeSessionStore";

export const newMockChallengeSessionStore =
  (): MockedObject<ChallengeSessionStore> =>
    ({
      create: vi.fn(),
      get: vi.fn(),
      update: vi.fn(),
      delete: vi.fn(),
    }) as unknown as MockedObject<ChallengeSessionStore>;
