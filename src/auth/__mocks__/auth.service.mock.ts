import { AuthService } from '../auth.service';
import { MAX_INT32 } from '../constants';
import { ChangePasswordRequest, SignUpRequest } from '../dto';
import { faker } from '@faker-js/faker';

export class MockAuthService extends AuthService {
  signUp(signUpRequest: SignUpRequest): Promise<number> {
    return Promise.resolve(signUpRequest.userId);
  }

  changePassword(
    changePasswordRequest: ChangePasswordRequest,
  ): Promise<number> {
    return Promise.resolve(changePasswordRequest.userId);
  }
  signIn(): Promise<string> {
    return Promise.resolve(faker.string.sample(64));
  }

  validateUser(): Promise<number> {
    return Promise.resolve(faker.number.int({ max: MAX_INT32 }));
  }
}
