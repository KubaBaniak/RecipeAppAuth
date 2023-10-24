import { TwoFactorAuth } from '@prisma/client';

export class MockTwoFactorAuthRepository {
  save2faSecretKeyForUserWithId(
    userId: number,
    secretKey: string,
  ): Promise<TwoFactorAuth> {
    return Promise.resolve({ userId, secretKey, isEnabled: false });
  }
}
