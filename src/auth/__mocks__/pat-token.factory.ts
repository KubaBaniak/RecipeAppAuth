import { faker } from '@faker-js/faker';
import { MAX_INT32 } from '../constants';
import { PersonalAccessTokens } from '@prisma/client';

type PatOverrides = {
  userId?: number;
  createdAt?: Date;
  token?: string;
  invalidatedAt?: Date | null;
};

export function createPat(overrides: PatOverrides = {}): PersonalAccessTokens {
  return {
    userId: overrides.userId ?? faker.number.int({ max: MAX_INT32 }),
    createdAt: overrides.createdAt ?? new Date(),
    token: overrides.token ?? faker.string.alphanumeric({ length: 32 }),
    invalidatedAt: overrides.invalidatedAt ?? null,
  };
}
