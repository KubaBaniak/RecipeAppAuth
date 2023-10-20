import { ChangePasswordRequest, SignUpRequest } from '../dto';
import { JwtService } from '@nestjs/jwt';
import { AuthService } from '../auth.service';
import { AUTH, MAX_INT32 } from '../constants';
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

  validateUser(): Promise<number> {
    return Promise.resolve(faker.number.int({ max: MAX_INT32 }));
  }

  createPersonalAccessToken(userId: number): Promise<string> {
    const jwtService = new JwtService();
    return Promise.resolve(
      jwtService.sign({ id: userId }, { secret: AUTH.PAT }),
    );
  }

  changePassword(
    changePasswordRequest: ChangePasswordRequest,
  ): Promise<number> {
    return Promise.resolve(changePasswordRequest.userId);
  }
}
