import { faker } from '@faker-js/faker';
import { TwoFactorAuth, TwoFactorAuthRecoveryKey } from '@prisma/client';
import { MAX_INT32, NUMBER_OF_2FA_RECOVERY_KEYS } from '../constants';
import { authenticator } from 'otplib';

type TwoFactorAuthOverrides = {
  userId?: number;
  isEnabled?: boolean;
  secretKey?: string;
};

type RecoveryKeysOverrides = {
  key?: string;
  isUsed?: boolean;
  usedAt?: Date;
  twoFactorAuthUserId?: number;
};

export function create2fa(
  overrides: TwoFactorAuthOverrides = {},
): TwoFactorAuth {
  return {
    userId: overrides.userId ?? faker.number.int({ max: MAX_INT32 }),
    isEnabled: overrides.isEnabled ?? false,
    secretKey: overrides.secretKey ?? authenticator.generateSecret(),
  };
}

export function createRecoveryKeys(
  overrides: RecoveryKeysOverrides = {},
): TwoFactorAuthRecoveryKey[] {
  return Array.from({ length: NUMBER_OF_2FA_RECOVERY_KEYS }, () => {
    return {
      key: authenticator.generateSecret(),
      isUsed: overrides.isUsed || false,
      usedAt: overrides.usedAt || null,
      twoFactorAuthUserId:
        overrides.twoFactorAuthUserId || faker.number.int({ max: MAX_INT32 }),
    };
  });
}

export function createRecoveryKeysWithKeyAndIsUsed(secretKey?: string) {
  return Array.from({ length: NUMBER_OF_2FA_RECOVERY_KEYS }, () => {
    return {
      key: authenticator.generate(secretKey || authenticator.generateSecret()),
      isUsed: false,
    };
  });
}

export function createExpiredKey(key?: string): TwoFactorAuthRecoveryKey {
  return {
    key: key || authenticator.generate(authenticator.generateSecret()),
    isUsed: true,
    usedAt: new Date(),
    twoFactorAuthUserId: faker.number.int({ max: MAX_INT32 }),
  };
}
