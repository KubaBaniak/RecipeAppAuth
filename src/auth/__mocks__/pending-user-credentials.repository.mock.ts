import { PendingUserCredentials } from '@prisma/client';
import { faker } from '@faker-js/faker';

export class MockPendingUserCredentialsRepository {
  storePendingUserCredentials(
    userId: number,
    password: string,
  ): Promise<PendingUserCredentials> {
    return Promise.resolve({ userId, password });
  }

  getPendingUserCredentialsById(
    userId: number,
  ): Promise<PendingUserCredentials | null> {
    return Promise.resolve({
      userId,
      password: faker.internet.password({ length: 64 }),
    });
  }

  removePendingUserCredentialsById(
    userId: number,
  ): Promise<PendingUserCredentials> {
    return Promise.resolve({
      userId,
      password: faker.internet.password({ length: 64 }),
    });
  }
}
