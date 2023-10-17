import 'dotenv/config';

export const BCRYPT = {
  SALT: process.env.BCRYPT_SALT_ROUNDS ? +process.env.BCRYPT_SALT_ROUNDS : 10,
};

export const SECRETS = {
  AUTH: process.env.JWT_SECRET ?? 'DefaultAUTH',
  PAT: process.env.JWT_PAT_SECRET ?? 'DefaultPersonalAccessToken',
  ACCOUNT_ACTIVATION:
    process.env.JWT_ACCOUNT_ACTIVATION_SECRET ?? 'DefaultAccountActivation',
};

export const EXPIRY_TIMES_OF_SECRETS = {
  AUTH: process.env.JWT_EXPIRY_TIME ?? '1h',
  ACCOUNT_ACTIVATION: process.env.JWT_ACCOUNT_ACTIVATION_SECRET ?? '1d',
};

export const MAX_INT32 = 2147483647;

export enum Strategies {
  Local = 'local',
}
