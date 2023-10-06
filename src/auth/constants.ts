import 'dotenv/config';

export const BCRYPT = {
  SALT: process.env.BCRYPT_SALT_ROUNDS ? +process.env.BCRYPT_SALT_ROUNDS : 10,
};

export const MAX_INT32 = 2147483647;

export const SERVICE = { name: 'Recipe App' };

export const NUMBER_OF_2FA_RECOVERY_TOKENS = 8;

export const STRATEGY = {
  bearer: 'jwt.bearer',
  pat: 'jwt.pat',
  twoFactor: '2fa.bearer',
  passwordReset: 'jwt.passwordReset',
  local: 'local',
};
