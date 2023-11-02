import { Controller, HttpCode } from '@nestjs/common';
import { AuthService } from './auth.service';
import {
  ChangePasswordRequest,
  Create2faQrCodeRequest,
  Create2faQrCodeResponse,
  CreatePatRequest,
  CreatePatResponse,
  Disable2faRequest,
  Enable2faRequest,
  RecoveryKeysRespnse,
  RegenerateRecoveryKeysRequest,
  SignInRequest,
  SignInResponse,
  SignUpRequest,
  SignUpResponse,
  Verify2faRequest,
} from './dto';
import {
  ApiTags,
  ApiBadRequestResponse,
  ApiOperation,
  ApiForbiddenResponse,
} from '@nestjs/swagger';
import { RabbitRPC } from '@golevelup/nestjs-rabbitmq';
import { ReplyErrorCallback } from './error-callback';

@Controller('auth')
@ApiTags('Authentication')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @RabbitRPC({
    exchange: 'authentication',
    routingKey: 'signup',
    errorHandler: ReplyErrorCallback,
  })
  @HttpCode(201)
  @ApiOperation({ summary: 'Add user to database' })
  @ApiBadRequestResponse({ description: 'Wrong credentials provided' })
  @ApiForbiddenResponse({
    description: 'Cannot add User to database, use different credentials',
  })
  @RabbitRPC({
    exchange: 'authentication',
    routingKey: 'signup',
    errorHandler: ReplyErrorCallback,
  })
  async signUp(test: SignUpRequest): Promise<SignUpResponse> {
    const userId = await this.authService.signUp(test);

    const accountActivationToken =
      await this.authService.generateAccountActivationToken(userId);

    return SignUpResponse.from(accountActivationToken);
  }

  @HttpCode(200)
  @ApiOperation({ summary: 'Authenticate user' })
  @RabbitRPC({
    exchange: 'authentication',
    routingKey: 'signin',
    errorHandler: ReplyErrorCallback,
  })
  async signIn(signInRequest: SignInRequest): Promise<SignInResponse> {
    const accessToken = await this.authService.signIn(signInRequest);

    return SignInResponse.from(accessToken);
  }

  @HttpCode(200)
  @ApiOperation({ summary: 'Validate user' })
  @RabbitRPC({
    exchange: 'authentication',
    routingKey: 'validate-user',
    errorHandler: ReplyErrorCallback,
  })
  async validateUser(validationData: SignInRequest): Promise<number> {
    const validatedUserId = await this.authService.validateUser(validationData);

    return validatedUserId;
  }

  @HttpCode(200)
  @ApiOperation({ summary: 'Validate jwt Token' })
  @RabbitRPC({
    exchange: 'authentication',
    routingKey: 'validate-jwt-token',
    errorHandler: ReplyErrorCallback,
  })
  async validateAuthToken({ token }: { token: string }): Promise<number> {
    const jwtPayload = await this.authService.validateAuthToken(token);

    return jwtPayload.id;
  }

  @HttpCode(201)
  @ApiOperation({ summary: 'Add personal access token for user' })
  @RabbitRPC({
    exchange: 'authentication',
    routingKey: 'add-personal-access-token',
    errorHandler: ReplyErrorCallback,
  })
  async createPat(
    createPatRequest: CreatePatRequest,
  ): Promise<CreatePatResponse> {
    const personalAccessToken =
      await this.authService.createPersonalAccessToken(createPatRequest.userId);

    return CreatePatResponse.from(personalAccessToken);
  }

  @HttpCode(200)
  @ApiOperation({ summary: 'Generates token for password reset' })
  @RabbitRPC({
    exchange: 'authentication',
    routingKey: 'generate-password-reset-token',
    errorHandler: ReplyErrorCallback,
  })
  async generatePasswordResetToken({
    userId,
  }: {
    userId: number;
  }): Promise<string> {
    return this.authService.generateResetPasswordToken(userId);
  }

  @HttpCode(200)
  @ApiOperation({ summary: 'Changes password of the user' })
  @RabbitRPC({
    exchange: 'authentication',
    routingKey: 'change-password',
    errorHandler: ReplyErrorCallback,
  })
  async changePassword(
    changePasswordRequest: ChangePasswordRequest,
  ): Promise<number> {
    return this.authService.changePassword(changePasswordRequest);
  }

  @HttpCode(200)
  @RabbitRPC({
    exchange: 'authentication',
    routingKey: 'activate-account',
    errorHandler: ReplyErrorCallback,
  })
  async activateAccount({ token }: { token: string }): Promise<number> {
    const { id: userId } = await this.authService.verifyAccountActivationToken(
      token,
    );

    await this.authService.activateAccount(userId);

    return userId;
  }

  @HttpCode(201)
  @ApiOperation({
    summary:
      'Creates QR code for user to scan it for auth app (like Google Authenticator)',
  })
  @RabbitRPC({
    exchange: 'authentication',
    routingKey: 'create-2fa-qrcode',
    errorHandler: ReplyErrorCallback,
  })
  async create2faQrCode(
    create2faQrCodeRequest: Create2faQrCodeRequest,
  ): Promise<Create2faQrCodeResponse> {
    const qrCode = await this.authService.createQrCodeFor2fa(
      create2faQrCodeRequest.userId,
    );

    return Create2faQrCodeResponse.from(qrCode);
  }

  @HttpCode(200)
  @ApiOperation({
    summary: 'Enables 2FA authentication for user',
  })
  @RabbitRPC({
    exchange: 'authentication',
    routingKey: 'enable-2fa',
    errorHandler: ReplyErrorCallback,
  })
  async enable2FA(
    enable2faRequest: Enable2faRequest,
  ): Promise<RecoveryKeysRespnse> {
    const recoveryKeys = await this.authService.enable2fa(
      enable2faRequest.userId,
      enable2faRequest.token,
    );

    return RecoveryKeysRespnse.from(recoveryKeys);
  }

  @HttpCode(200)
  @ApiOperation({ summary: 'Disables 2FA for logged user' })
  @RabbitRPC({
    exchange: 'authentication',
    routingKey: 'disable-2fa',
    errorHandler: ReplyErrorCallback,
  })
  async disable2fa(disable2faRequest: Disable2faRequest): Promise<number> {
    const twoFactorObject = await this.authService.disable2fa(
      disable2faRequest.userId,
    );

    return twoFactorObject.userId;
  }

  @HttpCode(200)
  @ApiOperation({ summary: 'Authenticate with 2FA to login' })
  @RabbitRPC({
    exchange: 'authentication',
    routingKey: 'verify-2fa',
    errorHandler: ReplyErrorCallback,
  })
  async verify2FA(verify2faRequest: Verify2faRequest): Promise<SignInResponse> {
    const accessToken = await this.authService.verify2fa(
      verify2faRequest.userId,
      verify2faRequest.token,
    );

    return SignInResponse.from(accessToken);
  }

  @HttpCode(201)
  @ApiOperation({ summary: 'Regenerate recovery keys for 2FA' })
  @RabbitRPC({
    exchange: 'authentication',
    routingKey: 'regenerate-2fa-recovery-keys',
    errorHandler: ReplyErrorCallback,
  })
  async regenerateRecoveryKeys(
    regenerateRecoveryKeysRequest: RegenerateRecoveryKeysRequest,
  ): Promise<RecoveryKeysRespnse> {
    const recoveryKeys = await this.authService.generate2faRecoveryKeys(
      regenerateRecoveryKeysRequest.userId,
    );

    return RecoveryKeysRespnse.from(recoveryKeys);
  }
}
