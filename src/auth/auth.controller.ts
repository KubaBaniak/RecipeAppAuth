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
import { MessagePattern, Payload } from '@nestjs/microservices';

@Controller('auth')
@ApiTags('Authentication')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @HttpCode(201)
  @ApiOperation({ summary: 'Add user to database' })
  @ApiBadRequestResponse({ description: 'Wrong credentials provided' })
  @ApiForbiddenResponse({
    description: 'Cannot add User to database, use different credentials',
  })
  @MessagePattern('signup')
  async signUp(
    @Payload() signUpRequest: SignUpRequest,
  ): Promise<SignUpResponse> {
    const userId = await this.authService.signUp(signUpRequest);

    const accountActivationToken =
      await this.authService.generateAccountActivationToken(userId);

    return SignUpResponse.from(accountActivationToken);
  }

  @HttpCode(200)
  @ApiOperation({ summary: 'Authenticate user' })
  @MessagePattern('signin')
  async signIn(
    @Payload() signInRequest: SignInRequest,
  ): Promise<SignInResponse> {
    const accessToken = await this.authService.signIn(signInRequest);

    return SignInResponse.from(accessToken);
  }

  @HttpCode(200)
  @ApiOperation({ summary: 'Validate user' })
  @MessagePattern('validate-user')
  async validateUser(
    @Payload() validationData: SignInRequest,
  ): Promise<number> {
    const validatedUserId = await this.authService.validateUser(validationData);

    return validatedUserId;
  }

  @HttpCode(200)
  @ApiOperation({ summary: 'Validate jwt Token' })
  @MessagePattern('validate-auth-token')
  async validateAuthToken(
    @Payload() { token }: { token: string },
  ): Promise<number> {
    const jwtPayload = await this.authService.validateAuthToken(token);

    return jwtPayload.id;
  }

  @HttpCode(201)
  @ApiOperation({ summary: 'Add personal access token for user' })
  @MessagePattern('create-personal-access-token')
  async createPat(
    @Payload() createPatRequest: CreatePatRequest,
  ): Promise<CreatePatResponse> {
    const personalAccessToken =
      await this.authService.createPersonalAccessToken(createPatRequest.userId);

    return CreatePatResponse.from(personalAccessToken);
  }

  @HttpCode(200)
  @ApiOperation({ summary: 'Generates token for password reset' })
  @MessagePattern('generate-password-reset-token')
  async generatePasswordResetToken(
    @Payload() { userId }: { userId: number },
  ): Promise<string> {
    return await this.authService.generateResetPasswordToken(userId);
  }

  @HttpCode(200)
  @ApiOperation({ summary: 'Changes password of the user' })
  @MessagePattern('change-password')
  async changePassword(
    @Payload() changePasswordRequest: ChangePasswordRequest,
  ): Promise<number> {
    return this.authService.changePassword(changePasswordRequest);
  }

  @HttpCode(200)
  @MessagePattern('activate-account')
  async activateAccount(
    @Payload() { token }: { token: string },
  ): Promise<number> {
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
  @MessagePattern('create-2fa-qrcode')
  async create2faQrCode(
    @Payload() create2faQrCodeRequest: Create2faQrCodeRequest,
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
  @MessagePattern('enable-2fa')
  async enable2FA(
    @Payload() enable2faRequest: Enable2faRequest,
  ): Promise<RecoveryKeysRespnse> {
    const recoveryKeys = await this.authService.enable2fa(
      enable2faRequest.userId,
      enable2faRequest.token,
    );

    return RecoveryKeysRespnse.from(recoveryKeys);
  }

  @HttpCode(200)
  @ApiOperation({ summary: 'Disables 2FA for logged user' })
  @MessagePattern('disable-2fa')
  async disable2fa(
    @Payload() disable2faRequest: Disable2faRequest,
  ): Promise<number> {
    const twoFactorObject = await this.authService.disable2fa(
      disable2faRequest.userId,
    );

    return twoFactorObject.userId;
  }

  @HttpCode(200)
  @ApiOperation({ summary: 'Authenticate with 2FA to login' })
  @MessagePattern('verify-2fa')
  async verify2FA(
    @Payload() verify2faRequest: Verify2faRequest,
  ): Promise<SignInResponse> {
    const accessToken = await this.authService.verify2fa(
      verify2faRequest.userId,
      verify2faRequest.token,
    );

    return SignInResponse.from(accessToken);
  }

  @HttpCode(201)
  @ApiOperation({ summary: 'Regenerate recovery keys for 2FA' })
  @MessagePattern('regenerate-2fa-recovery-keys')
  async regenerateRecoveryKeys(
    @Payload() regenerateRecoveryKeysRequest: RegenerateRecoveryKeysRequest,
  ): Promise<RecoveryKeysRespnse> {
    const recoveryKeys = await this.authService.generate2faRecoveryKeys(
      regenerateRecoveryKeysRequest.userId,
    );

    return RecoveryKeysRespnse.from(recoveryKeys);
  }
}
