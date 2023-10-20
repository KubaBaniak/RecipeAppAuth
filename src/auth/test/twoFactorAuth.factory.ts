import { faker } from '@faker-js/faker';
import { TwoFactorAuth } from '@prisma/client';
import { MAX_INT32 } from '../constants';
import { authenticator } from 'otplib';

type TwoFactorAuthOverrides = {
  userId?: number;
  isEnabled?: boolean;
  secretKey?: string;
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
