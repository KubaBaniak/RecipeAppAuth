import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { BCRYPT, NUMBER_OF_2FA_RECOVERY_KEYS, SERVICE_NAME } from './constants';
import * as bcrypt from 'bcryptjs';
import { SignInRequest, SignUpRequest, UserCredentialsRequest } from './dto';
import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import 'dotenv/config';
import qrcode from 'qrcode';
import { authenticator } from 'otplib';
import {
  TwoFactorAuthRepository,
  UserCredentialsRepository,
} from './repositories';
import { TwoFactorAuth } from '@prisma/client';

@Injectable()
export class AuthService {
  constructor(
    private readonly userCredentialsRepository: UserCredentialsRepository,
    private readonly twoFactorAuthRepository: TwoFactorAuthRepository,
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
      process.env.JWT_SECRET ?? 'Default_jwt_secret',
      process.env.JWT_EXPIRY_TIME ?? '1h',
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

  async createQrCodeFor2fa(userId: number): Promise<string> {
    const service = SERVICE_NAME;
    const secretKey = authenticator.generateSecret();

    const otpauth = authenticator.keyuri(String(userId), service, secretKey);

    await this.twoFactorAuthRepository.save2faSecretKeyForUserWithId(
      userId,
      secretKey,
    );

    return qrcode.toDataURL(otpauth);
  }

  async generate2faRecoveryKeys(userId: number): Promise<string[]> {
    const recoveryKeys = Array.from(
      { length: NUMBER_OF_2FA_RECOVERY_KEYS },
      () => {
        return { key: authenticator.generateSecret() };
      },
    );

    await this.twoFactorAuthRepository.saveRecoveryKeysForUserWithId(
      userId,
      recoveryKeys,
    );

    return recoveryKeys.map((keyObject) => keyObject.key);
  }

  async enable2fa(userId: number, providedToken: string): Promise<string[]> {
    const twoFactorAuth =
      await this.twoFactorAuthRepository.get2faForUserWithId(userId);

    if (twoFactorAuth?.isEnabled) {
      throw new BadRequestException('You have already enabled 2FA');
    }

    if (!twoFactorAuth?.secretKey) {
      throw new ForbiddenException(
        'Cannot enable QR Code. Re-generate QR code, scan it and try again with new token',
      );
    }
    if (authenticator.check(providedToken, twoFactorAuth.secretKey)) {
      await this.twoFactorAuthRepository.enable2faForUserWithId(userId);
      return this.generate2faRecoveryKeys(userId);
    } else {
      throw new BadRequestException('Incorrect 2FA token');
    }
  }

  async disable2fa(userId: number): Promise<TwoFactorAuth> {
    const twoFactorAuth =
      await this.twoFactorAuthRepository.get2faForUserWithId(userId);

    if (!twoFactorAuth) {
      throw new BadRequestException(
        'Could not disable 2FA, because it was not enabled',
      );
    }
    return this.twoFactorAuthRepository.disable2faForUserWithId(userId);
  }
}
