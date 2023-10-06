import { AuthService } from '../auth.service';
import { ChangePasswordRequest, SignUpRequest } from '../dto';

export class MockAuthService extends AuthService {
  signUp(signUpRequest: SignUpRequest): Promise<number> {
    return Promise.resolve(signUpRequest.userId);
  }

  changePassword(
    changePasswordRequest: ChangePasswordRequest,
  ): Promise<number> {
    return Promise.resolve(changePasswordRequest.userId);
  }
}
