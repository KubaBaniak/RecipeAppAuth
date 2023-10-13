import { PersonalAccessTokenRepository } from '../repositories';
import { PersonalAccessToken } from '@prisma/client';
import { createPat } from './pat-token.factory';

export class MockPatRepository extends PersonalAccessTokenRepository {
  savePersonalAccessToken(
    userId: number,
    token: string,
  ): Promise<PersonalAccessToken> {
    return Promise.resolve(createPat({ userId, token }));
  }

  getValidPatForUserId(userId: number): Promise<PersonalAccessToken | null> {
    return Promise.resolve(createPat({ userId }));
  }

  invalidatePatForUserId(): Promise<void> {
    return Promise.resolve();
  }
}
