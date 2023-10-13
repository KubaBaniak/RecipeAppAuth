import 'dotenv/config';

export const BCRYPT = {
  SALT: process.env.BCRYPT_SALT_ROUNDS ? +process.env.BCRYPT_SALT_ROUNDS : 10,
};

export const SECRETS = {
  PAT: process.env.JWT_PAT_SECRET ? process.env.JWT_PAT_SECRET : 'DefaultPAT',
};

export const MAX_INT32 = 2147483647;
