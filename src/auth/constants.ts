import 'dotenv/config';

export const BCRYPT = {
  SALT: process.env.BCRYPT_SALT_ROUNDS ? +process.env.BCRYPT_SALT_ROUNDS : 10,
};

export const MAX_INT32 = 2147483647;

export enum Strategies {
  Local = 'local',
}
