import { TwoFactorAuth, TwoFactorAuthRecoveryKey } from '@prisma/client';
import {
  create2fa,
  createExpiredKey,
  createRecoveryKeysWithKeyAndIsUsed,
} from '../test/twoFactorAuth.factory';

export class MockTwoFactorAuthRepository {
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

  expire2faRecoveryKey(key: string): Promise<TwoFactorAuthRecoveryKey> {
    return Promise.resolve(createExpiredKey(key));
  }

  saveRecoveryKeysForUserWithId(): Promise<void> {
    return Promise.resolve();
  }

  getRecoveryKeysForUserWithId(
    userId: number,
  ): Promise<{ key: string; isUsed: boolean }[] | null> {
    return Promise.all(
      createRecoveryKeysWithKeyAndIsUsed({ twoFactorAuthUserId: userId }),
    );
  }
}
