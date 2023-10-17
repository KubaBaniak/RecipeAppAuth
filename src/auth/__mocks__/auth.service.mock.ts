import { AuthService } from '../auth.service';
import { MAX_INT32 } from '../constants';
import { SignUpRequest } from '../dto';
import { faker } from '@faker-js/faker';

export class MockAuthService extends AuthService {
  signUp(signUpRequest: SignUpRequest): Promise<number> {
    return Promise.resolve(signUpRequest.userId);
  }

  createPersonalAccessToken(): Promise<string> {
    return Promise.resolve(faker.string.alphanumeric(32));
  }
  signIn(): Promise<string> {
    return Promise.resolve(faker.string.sample(64));
  }

  generateAccountActivationToken(): string {
    return faker.string.sample(64);
  }

  validateUser(): Promise<number> {
    return Promise.resolve(faker.number.int({ max: MAX_INT32 }));
  }
}
