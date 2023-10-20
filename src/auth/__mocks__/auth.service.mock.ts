import { AuthService } from '../auth.service';
import { MAX_INT32 } from '../constants';
import { SignUpRequest } from '../dto';
import { faker } from '@faker-js/faker';

export class MockAuthService extends AuthService {
  signUp(signUpRequest: SignUpRequest): Promise<number> {
    return Promise.resolve(signUpRequest.userId);
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

  validateUser(): Promise<number> {
    return Promise.resolve(faker.number.int({ max: MAX_INT32 }));
  }

  createQrCodeFor2fa(): Promise<string> {
    return Promise.resolve(faker.string.alphanumeric());
  }

  enable2fa(): Promise<string[]> {
    return Promise.all(
      Array.from({ length: 8 }, () => {
        return faker.string.alphanumeric({ length: 8 });
      }),
    );
  }

  disable2fa(
    userId: number,
  ): Promise<{ userId: number; secretKey: string; isEnabled: boolean }> {
    return Promise.resolve({
      userId,
      secretKey: faker.string.alphanumeric({ length: 8 }),
      isEnabled: true,
    });
  }
}
