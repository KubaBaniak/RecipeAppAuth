import { SignUpRequest } from '../dto';
import { faker } from '@faker-js/faker';

export class MockAuthService {
  signUp(signUpRequest: SignUpRequest): number {
    return signUpRequest.userId;
  }
  signIn(): Promise<string> {
    return Promise.resolve(faker.string.sample(64));
  }
  generateAccountActivationToken(): string {
    return faker.string.sample(64);
  }

  verifyAccountActivationToken(): Promise<{ id: number }> {
    return Promise.resolve({ id: faker.number.int() });
  }

  validateUser(): Promise<void> {
    return Promise.resolve();
  }
}
