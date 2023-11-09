import { faker } from '@faker-js/faker';
import { UserCredentials } from '@prisma/client';
import * as bcrypt from 'bcryptjs';
import { BCRYPT, MAX_INT32 } from '../constants';

type UserCredentialsOverrides = {
  userId?: number;
  password?: string;
};

type UserCredentialsWithHashedPasswordOverrides = {
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

export const generateUserCredentialsWithHashedPassword = async function (
  overrides: UserCredentialsWithHashedPasswordOverrides = {},
): Promise<UserCredentials> {
  return {
    userId: overrides.userId ?? faker.number.int({ max: MAX_INT32 }),
    password: await bcrypt.hash(
      overrides.password ?? faker.internet.password({ length: 64 }),
      BCRYPT.SALT,
    ),
  };
};
