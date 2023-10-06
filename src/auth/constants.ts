import 'dotenv/config';

export const BCRYPT = {
  SALT: process.env.BCRYPT_SALT_ROUNDS as string,
};

export const MAX_INT32 = 2147483647;
