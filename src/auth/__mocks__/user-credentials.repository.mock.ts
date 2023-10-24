import { faker } from '@faker-js/faker';
import { UserCredentials } from '@prisma/client';
import * as bcrypt from 'bcryptjs';
import { BCRYPT } from '../constants';

export class MockUserCredentialsRepository {
  storeUserCredentials(
    userId: number,
    password: string,
  ): Promise<UserCredentials> {
    return Promise.resolve({ userId, password });
  }

  async getUserCredentialsByUserId(
    userId: number,
  ): Promise<UserCredentials | null> {
    return Promise.resolve({
      userId,
      password: faker.internet.password({ length: 64 }),
    });
  }

  async updateUserPasswordByUserId(
    userId: number,
    newPassword: string,
  ): Promise<UserCredentials> {
    return Promise.resolve({
      userId,
      password: await bcrypt.hash(newPassword, BCRYPT.SALT),
    });
  }
}
