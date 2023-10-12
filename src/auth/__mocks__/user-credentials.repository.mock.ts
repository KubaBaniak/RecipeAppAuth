import { faker } from '@faker-js/faker';
import { UserCredentialsRepository } from '../user-credentials.repository';
import { UserCredentials } from '@prisma/client';

export class MockUserCredentialsRepository extends UserCredentialsRepository {
  storeUserCredentials(
    userId: number,
    password: string,
  ): Promise<UserCredentials> {
    return Promise.resolve({ userId, password });
  }

  async getUserCredentialsByUserId(): Promise<string | null> {
    return Promise.resolve(faker.internet.password());
  }
}
