import { ChangePasswordRequest, SignUpRequest } from '../dto';
import { JwtService } from '@nestjs/jwt';
import { AUTH, MAX_INT32 } from '../constants';
import { faker } from '@faker-js/faker';

export class MockAuthService {
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

  async verifyAccountActivationToken(): Promise<{ id: number }> {
    return Promise.resolve({ id: faker.number.int({ max: MAX_INT32 }) });
  }

  activateAccount(userId: number): Promise<number> {
    return Promise.resolve(userId);
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
