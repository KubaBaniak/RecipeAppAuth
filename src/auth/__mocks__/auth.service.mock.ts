import { faker } from '@faker-js/faker';
import { AuthService } from '../auth.service';
import { SignUpRequest } from '../dto';

export class MockAuthService extends AuthService {
  signUp(signUpRequest: SignUpRequest): Promise<number> {
    return Promise.resolve(signUpRequest.userId);
  }

  createPersonalAccessToken(): Promise<string> {
    return Promise.resolve(faker.string.alphanumeric(32));
  }
}
