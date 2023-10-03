import 'dotenv/config';

export const BCRYPT = {
  salt: +process.env.BCRYPT_SALT_ROUNDS,
};
