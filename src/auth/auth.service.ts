import {
  ConflictException,
  UnauthorizedException,
  Injectable,
} from '@nestjs/common';
import { BCRYPT, EXPIRY_TIMES_OF_SECRETS, SECRETS } from './constants';
import * as bcrypt from 'bcryptjs';
import {
  PersonalAccessTokenRepository,
  UserCredentialsRepository,
} from './repositories';
import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import 'dotenv/config';

import { SignInRequest, SignUpRequest, UserCredentialsRequest } from './dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly userCredentialsRepository: UserCredentialsRepository,
    private readonly personalAccessTokenRepository: PersonalAccessTokenRepository,
    private readonly jwtService: JwtService,
  ) {}

  async generateToken(
    id: number,
    secret: string,
    time?: string,
  ): Promise<string> {
    const payload = { id };
    const options: JwtSignOptions = { secret };

    if (time) {
      options.expiresIn = time;
    }

    return this.jwtService.signAsync(payload, options);
  }

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

  async signIn(signInRequest: SignInRequest): Promise<string> {
    const userCredentials =
      await this.userCredentialsRepository.getUserCredentialsByUserId(
        signInRequest.userId,
      );

    if (!userCredentials) {
      throw new UnauthorizedException();
    }

    return this.generateToken(
      signInRequest.userId,
      SECRETS.AUTH,
      EXPIRY_TIMES_OF_SECRETS.AUTH,
    );
  }

  async validateUser(request: UserCredentialsRequest): Promise<number> {
    const userCredentials =
      await this.userCredentialsRepository.getUserCredentialsByUserId(
        request.userId,
      );

    if (!userCredentials) {
      throw new UnauthorizedException();
    }

    const isMatch = await bcrypt.compare(
      request.password,
      userCredentials.password,
    );

    if (!isMatch) {
      throw new UnauthorizedException();
    }

    return userCredentials.userId;
  }

  async createPersonalAccessToken(userId: number): Promise<string> {
    const validPersonalAccessToken =
      await this.personalAccessTokenRepository.getValidPatForUserId(userId);

    if (validPersonalAccessToken) {
      this.personalAccessTokenRepository.invalidatePatForUserId(userId);
    }

    const personalAccessToken = await this.generateToken(userId, SECRETS.PAT);
    const { token } =
      await this.personalAccessTokenRepository.savePersonalAccessToken(
        userId,
        personalAccessToken,
      );
    return token;
  }
}
