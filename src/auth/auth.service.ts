import { ConflictException, Injectable } from '@nestjs/common';
import { BCRYPT } from './constants';
import * as bcrypt from 'bcryptjs';
import { ChangePasswordRequest, SignUpRequest } from './dto';
import { UserCredentialsRepository } from './repositories';

@Injectable()
export class AuthService {
  constructor(
    private readonly userCredentialsRepository: UserCredentialsRepository,
  ) {}

  async signUp(signUpRequest: SignUpRequest): Promise<number> {
    const { userId, password } = signUpRequest;

    const isUserInDb =
      await this.userCredentialsRepository.getUserCredentialsByUserId(userId);

    if (isUserInDb) {
      throw new ConflictException();
    }

    const hashedPassword = await bcrypt.hash(password, BCRYPT.SALT);

    const userCredentials =
      await this.userCredentialsRepository.storeUserCredentials(
        userId,
        hashedPassword,
      );

    return userCredentials.userId;
  }
  async changePassword(
    changePasswordRequest: ChangePasswordRequest,
  ): Promise<number> {
    const { userId, newPassword } = changePasswordRequest;
    const hashedPassword = await bcrypt.hash(newPassword, BCRYPT.SALT);

    const updatedCredentials =
      await this.userCredentialsRepository.updateUserPasswordByUserId(
        userId,
        hashedPassword,
      );

    return updatedCredentials.userId;
  }
}
