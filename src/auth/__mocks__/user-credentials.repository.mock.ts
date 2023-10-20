import { faker } from '@faker-js/faker';
import { UserCredentialsRepository } from '../repositories';
import { UserCredentials } from '@prisma/client';
import { MAX_INT32 } from '../constants';

export class MockUserCredentialsRepository extends UserCredentialsRepository {
  storeUserCredentials(
    userId: number,
    password: string,
  ): Promise<UserCredentials> {
    return Promise.resolve({ userId, password });
  }

  async getUserCredentialsByUserId(): Promise<UserCredentials | null> {
    return Promise.resolve({
      userId: faker.number.int({ max: MAX_INT32 }),
      password: faker.internet.password({ length: 64 }),
    });
  }
}
