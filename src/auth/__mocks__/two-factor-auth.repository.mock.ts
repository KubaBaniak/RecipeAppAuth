import { TwoFactorAuthRepository } from '../repositories';
import { TwoFactorAuth } from '@prisma/client';
import { create2fa } from '../test/twoFactorAuth.factory';

export class MockTwoFactorAuthRepository extends TwoFactorAuthRepository {
  save2faSecretKeyForUserWithId(
    userId: number,
    secretKey: string,
  ): Promise<TwoFactorAuth> {
    return Promise.resolve({ userId, secretKey, isEnabled: false });
  }

  get2faForUserWithId(userId: number): Promise<TwoFactorAuth | null> {
    return Promise.resolve(create2fa({ userId }));
  }

  enable2faForUserWithId(userId: number): Promise<TwoFactorAuth> {
    return Promise.resolve(create2fa({ userId }));
  }

  disable2faForUserWithId(userId: number): Promise<TwoFactorAuth> {
    return Promise.resolve(create2fa({ userId }));
  }
}
