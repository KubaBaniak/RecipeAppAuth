import { Injectable } from '@nestjs/common';
import {
  AUTH,
  BCRYPT,
  NUMBER_OF_2FA_RECOVERY_KEYS,
  SERVICE_NAME,
} from './constants';
import {
  PersonalAccessTokenRepository,
  UserCredentialsRepository,
  PendingUserCredentialsRepository,
  TwoFactorAuthRepository,
} from './repositories';
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
import { RpcException } from '@nestjs/microservices';

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
      throw new RpcException({ message: 'Forbidden', status: 403 });
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
    const [user2fa, userCredentials] = await Promise.all([
      this.twoFactorAuthRepository.get2faForUserWithId(signInRequest.userId),
      this.userCredentialsRepository.getUserCredentialsByUserId(
        signInRequest.userId,
      ),
    ]);

    if (!userCredentials) {
      throw new RpcException({ message: 'Unauthorized', status: 401 });
    }

    if (user2fa?.isEnabled) {
      if (!signInRequest.token) {
        throw new RpcException({ message: 'Unauthorized', status: 401 });
      }
      return this.verify2fa(userCredentials.userId, signInRequest.token);
    }

    return this.generateToken(
      signInRequest.userId,
      AUTH.AUTH_TOKEN,
      AUTH.AUTH_TOKEN_EXPIRY_TIME,
    );
  }

  async validateAuthToken(token: string): Promise<{ id: number }> {
    try {
      return this.jwtService.verify(token, {
        secret: AUTH.AUTH_TOKEN,
      });
    } catch {
      throw new RpcException({
        message: 'Unauthorized. Invalid Token',
        status: 401,
      });
    }
  }

  async validateUser(request: UserCredentialsRequest): Promise<number> {
    const userCredentials =
      await this.userCredentialsRepository.getUserCredentialsByUserId(
        request.userId,
      );

    if (!userCredentials) {
      throw new RpcException({ message: 'Unauthorized', status: 401 });
    }

    const isMatch = await bcrypt.compare(
      request.password,
      userCredentials.password,
    );

    if (!isMatch) {
      throw new RpcException({ message: 'Unauthorized', status: 401 });
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

  async generateResetPasswordToken(userId: number): Promise<string> {
    const userCredentials =
      await this.userCredentialsRepository.getUserCredentialsByUserId(userId);

    if (!userCredentials) {
      return '';
    }

    return this.generateToken(
      userCredentials.userId,
      AUTH.PASSWORD_RESET,
      AUTH.PASSWORD_RESET_TIME,
    );
  }

  async generateAccountActivationToken(userId: number): Promise<string> {
    return this.generateToken(
      userId,
      AUTH.ACCOUNT_ACTIVATION,
      AUTH.ACCOUNT_ACTIVATION_EXPIRY_TIME,
    );
  }

  async verifyAccountActivationToken(
    jwtToken: string,
  ): Promise<{ id: number }> {
    try {
      return this.jwtService.verify(jwtToken, {
        secret: AUTH.ACCOUNT_ACTIVATION,
      });
    } catch {
      throw new RpcException({
        message:
          'Invalid token. Please provide a valid token to activate account',
        status: 401,
      });
    }
  }

  async activateAccount(userId: number): Promise<number> {
    const userData =
      await this.pendingUserCredentialsRepository.getPendingUserCredentialsById(
        userId,
      );

    if (!userData) {
      throw new RpcException({
        message:
          'User account data for activation was not found. Please ensure you provided correct token or check if User is already activated',
        status: 404,
      });
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

  async enable2fa(userId: number, token: string): Promise<string[]> {
    const twoFactorAuth =
      await this.twoFactorAuthRepository.get2faForUserWithId(userId);

    if (twoFactorAuth?.isEnabled) {
      throw new RpcException({
        message: 'You have already enabled 2FA',
        status: 400,
      });
    }

    if (!twoFactorAuth?.secretKey) {
      throw new RpcException({
        message:
          'Cannot enable QR Code. Re-generate QR code, scan it and try again with new token',
        status: 403,
      });
    }

    if (authenticator.check(token, twoFactorAuth.secretKey)) {
      await this.twoFactorAuthRepository.enable2faForUserWithId(userId);
      return this.generate2faRecoveryKeys(userId);
    } else {
      throw new RpcException({ message: 'Incorrect 2FA token', status: 400 });
    }
  }

  async disable2fa(userId: number): Promise<TwoFactorAuth> {
    const twoFactorAuth =
      await this.twoFactorAuthRepository.get2faForUserWithId(userId);

    if (!twoFactorAuth) {
      throw new RpcException({
        message: 'Could not disable 2FA, because it was not enabled',
        status: 400,
      });
    }

    return this.twoFactorAuthRepository.disable2faForUserWithId(userId);
  }

  async verify2fa(userId: number, token: string): Promise<string> {
    const twoFactorAuth =
      await this.twoFactorAuthRepository.get2faForUserWithId(userId);
    const keys =
      await this.twoFactorAuthRepository.getRecoveryKeysForUserWithId(userId);

    if (!twoFactorAuth || !twoFactorAuth.isEnabled) {
      throw new RpcException({ message: '2FA is not enabled', status: 403 });
    }

    if (keys?.some(({ key, isUsed }) => key === token && !isUsed)) {
      await this.twoFactorAuthRepository.expire2faRecoveryKey(token);
      return this.generateToken(
        userId,
        process.env.JWT_SECRET ?? 'Default_jwt_secret',
        process.env.JWT_EXPIRY_TIME ?? '1h',
      );
    }

    if (authenticator.check(token, twoFactorAuth?.secretKey)) {
      return this.generateToken(
        userId,
        process.env.JWT_SECRET ?? 'Default_jwt_secret',
        process.env.JWT_EXPIRY_TIME ?? '1h',
      );
    }

    throw new RpcException({ message: 'Incorrect 2FA token', status: 400 });
  }
}
