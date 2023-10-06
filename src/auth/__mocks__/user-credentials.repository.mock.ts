import { faker } from '@faker-js/faker';
import { UserCredentialsRepository } from '../repositories';
import { UserCredentials } from '@prisma/client';
import * as bcrypt from 'bcryptjs';
import { BCRYPT } from '../constants';

export class MockUserCredentialsRepository extends UserCredentialsRepository {
  storeUserCredentials(
    userId: number,
    password: string,
  ): Promise<UserCredentials> {
    return Promise.resolve({ userId, password });
  }

  async getUserCredentialsByUserId(userId: number): Promise<UserCredentials> {
    return Promise.resolve({ userId, password: faker.internet.password() });
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
