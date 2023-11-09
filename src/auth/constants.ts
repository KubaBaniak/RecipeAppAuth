import 'dotenv/config';

export const BCRYPT = {
  SALT: process.env.BCRYPT_SALT_ROUNDS ? +process.env.BCRYPT_SALT_ROUNDS : 10,
};

export const SERVICE_NAME = 'Recipe App';

export const NUMBER_OF_2FA_RECOVERY_KEYS = 8;

export const RABBITMQ_URL_ADDRESS =
  process.env.RABBITMQ_ADDRESS ?? 'amqp://127.0.0.1:5672';

export const AUTH = {
  AUTH_TOKEN: process.env.JWT_SECRET ?? 'DefaultAUTH',
  AUTH_TOKEN_EXPIRY_TIME: process.env.JWT_EXPIRY_TIME ?? '1h',
  PAT: process.env.JWT_PAT_SECRET ?? 'DefaultPersonalAccessToken',
  ACCOUNT_ACTIVATION:
    process.env.JWT_ACCOUNT_ACTIVATION_SECRET ?? 'DefaultAccountActivation',
  ACCOUNT_ACTIVATION_EXPIRY_TIME:
    process.env.ACCOUNT_ACTIVATION_EXPIRY_TIME ?? '1d',
  PASSWORD_RESET: process.env.PASSWORD_RESET ?? 'DefaultPasswordReset',
  PASSWORD_RESET_TIME: process.env.PASSWORD_RESET_TIME ?? '1d',
};

export const MAX_INT32 = 2147483647;

export enum Strategies {
  Local = 'local',
}
