import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { BCRYPT } from './constants';
import * as bcrypt from 'bcryptjs';
import { SignInRequest, SignUpRequest, UserCredentialsRequest } from './dto';
import { UserCredentialsRepository } from './user-credentials.repository';
import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import 'dotenv/config';

@Injectable()
export class AuthService {
  constructor(
    private readonly userCredentialsRepository: UserCredentialsRepository,
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
      process.env.JWT_SECRET ? process.env.JWT_SECRET : 'Default_jwt_secret',
      process.env.JWT_EXPIRY_TIME ? process.env.JWT_EXPIRY_TIME : '1h',
    );
  }

  async validateUser(request: UserCredentialsRequest): Promise<number> {
    const userPassword =
      await this.userCredentialsRepository.getUserCredentialsByUserId(
        request.userId,
      );

    if (!userPassword) {
      throw new UnauthorizedException();
    }

    const isMatch = await bcrypt.compare(request.password, userPassword);

    if (!isMatch) {
      throw new UnauthorizedException();
    }

    return request.userId;
  }
}
