import 'dotenv/config';

export const BCRYPT = {
  salt: +process.env.BCRYPT_SALT_ROUNDS!,
};

export const MAX_INT32 = 2147483647;
