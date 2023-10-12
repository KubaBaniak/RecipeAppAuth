import { faker } from '@faker-js/faker';
import { UserCredentials } from '@prisma/client';
import { MAX_INT32 } from '../constants';

type UserCredentialsOverrides = {
  userId?: number;
  password?: string;
};

export const generateUserCredentials = function (
  overrides: UserCredentialsOverrides = {},
): UserCredentials {
  return {
    userId: overrides.userId ?? faker.number.int({ max: MAX_INT32 }),
    password: overrides.password ?? faker.internet.password({ length: 64 }),
  };
};
