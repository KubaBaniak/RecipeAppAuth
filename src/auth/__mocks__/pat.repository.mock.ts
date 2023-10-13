import { PersonalAccessTokenRepository } from '../repositories';
import { PersonalAccessTokens } from '@prisma/client';
import { createPat } from './pat-token.factory';

export class MockPatRepository extends PersonalAccessTokenRepository {
  savePersonalAccessToken(
    userId: number,
    token: string,
  ): Promise<PersonalAccessTokens> {
    return Promise.resolve(createPat({ userId, token }));
  }

  getValidPatForUserId(userId: number): Promise<PersonalAccessTokens | null> {
    return Promise.resolve(createPat({ userId }));
  }

  invalidatePatForUserId(): Promise<void> {
    return Promise.resolve();
  }
}
