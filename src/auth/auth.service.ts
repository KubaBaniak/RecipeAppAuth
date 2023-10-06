import { ConflictException, Injectable } from '@nestjs/common';
import { BCRYPT } from './constants';
import * as bcrypt from 'bcryptjs';
import { SignUpRequest } from './dto';
import { UserCredentialsRepository } from './user-credentials.repository';

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
}
