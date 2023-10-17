import {
  ConflictException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { BCRYPT, EXPIRY_TIMES_OF_SECRETS, SECRETS } from './constants';
import * as bcrypt from 'bcryptjs';
import { SignInRequest, SignUpRequest, UserCredentialsRequest } from './dto';
import {
  UserCredentialsRepository,
  PendingUserCredentialsRepository,
} from './repositories';
import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import 'dotenv/config';
@Injectable()
export class AuthService {
  constructor(
    private readonly userCredentialsRepository: UserCredentialsRepository,
    private readonly pendingUserCredentialsRepository: PendingUserCredentialsRepository,
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

    const [pendingUserCredentials, userCredentials] = await Promise.all([
      this.pendingUserCredentialsRepository.getPendingUserCredentialsById(
        userId,
      ),
      this.userCredentialsRepository.getUserCredentialsByUserId(userId),
    ]);

    if (pendingUserCredentials || userCredentials) {
      throw new ConflictException();
    }

    const hashedPassword = await bcrypt.hash(password, BCRYPT.SALT);

    const savedCredentials =
      await this.pendingUserCredentialsRepository.storePendingUserCredentials(
        userId,
        hashedPassword,
      );

    return savedCredentials.userId;
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

  async verifyAccountActivationToken(
    jwtToken: string,
  ): Promise<{ id: number }> {
    const invalidTokenMessage =
      'Invalid token. Please provide a valid token to activate account';

    try {
      return this.jwtService.verifyAsync(jwtToken, {
        secret: SECRETS.ACCOUNT_ACTIVATION,
      });
    } catch {
      throw new UnauthorizedException(invalidTokenMessage);
    }
  }

  async activateAccount(userId: number): Promise<number> {
    const userData =
      await this.pendingUserCredentialsRepository.getPendingUserCredentialsById(
        userId,
      );

    if (!userData) {
      throw new NotFoundException(
        'User account data for activation was not found. Please ensure you provided correct token or check if User is already activated',
      );
    }

    const activatedUserCredentials =
      await this.userCredentialsRepository.storeUserCredentials(
        userData.userId,
        userData.password,
      );

    await this.pendingUserCredentialsRepository.removePendingUserCredentialsById(
      userId,
    );

    return activatedUserCredentials.userId;
  }
}
