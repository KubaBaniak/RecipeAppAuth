import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import {
  PersonalAccessTokenRepository,
  UserCredentialsRepository,
  PendingUserCredentialsRepository,
  TwoFactorAuthRepository,
} from './repositories';
import {
  AUTH,
  BCRYPT,
  SERVICE_NAME,
  NUMBER_OF_2FA_RECOVERY_KEYS,
} from './constants';
import * as bcrypt from 'bcryptjs';
import {
  ChangePasswordRequest,
  SignInRequest,
  SignUpRequest,
  UserCredentialsRequest,
} from './dto';
import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import 'dotenv/config';
import qrcode from 'qrcode';
import { authenticator } from 'otplib';
import { TwoFactorAuth } from '@prisma/client';

@Injectable()
export class AuthService {
  constructor(
    private readonly userCredentialsRepository: UserCredentialsRepository,
    private readonly twoFactorAuthRepository: TwoFactorAuthRepository,
    private readonly pendingUserCredentialsRepository: PendingUserCredentialsRepository,
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
      AUTH.AUTH_TOKEN,
      AUTH.AUTH_TOKEN_EXPIRY_TIME,
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

    const personalAccessToken = await this.generateToken(userId, AUTH.PAT);
    const { token } =
      await this.personalAccessTokenRepository.savePersonalAccessToken(
        userId,
        personalAccessToken,
      );
    return token;
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

  async verifyAccountActivationToken(
    jwtToken: string,
  ): Promise<{ id: number }> {
    const invalidTokenMessage =
      'Invalid token. Please provide a valid token to activate account';
    try {
      return this.jwtService.verify(jwtToken, {
        secret: AUTH.ACCOUNT_ACTIVATION,
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
