import {
  Controller,
  Body,
  Post,
  HttpCode,
  UseGuards,
  Get,
  Query,
} from '@nestjs/common';
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
import { LocalAuthGuard } from './guards';

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
  @Post('signup')
  async signUp(@Body() signUpRequest: SignUpRequest): Promise<SignUpResponse> {
    const userId = await this.authService.signUp(signUpRequest);
    return { userId };
  }
  @HttpCode(200)
  @UseGuards(LocalAuthGuard)
  @ApiOperation({ summary: 'Authenticate user' })
  @Post('signin')
  async signIn(@Body() signInRequest: SignInRequest): Promise<SignInResponse> {
    const accessToken = await this.authService.signIn(signInRequest);

    return SignInResponse.from(accessToken);
  }

  @HttpCode(201)
  @ApiOperation({ summary: 'Add personal access token for user' })
  @Post('create-pat')
  async createPat(
    @Body() createPatRequest: CreatePatRequest,
  ): Promise<CreatePatResponse> {
    const personalAccessToken =
      await this.authService.createPersonalAccessToken(createPatRequest.userId);

    return CreatePatResponse.from(personalAccessToken);
  }

  @HttpCode(200)
  @ApiOperation({ summary: 'Changes password of the user' })
  @Post('change-password')
  async changePassword(
    @Body() changePasswordRequest: ChangePasswordRequest,
  ): Promise<void> {
    await this.authService.changePassword(changePasswordRequest);
  }

  @HttpCode(200)
  @Get('activate-account')
  async activateAccount(@Query('token') token: string): Promise<void> {
    const tokenData = await this.authService.verifyAccountActivationToken(
      token,
    );
    await this.authService.activateAccount(tokenData.id);
  }

  @HttpCode(201)
  @ApiOperation({
    summary:
      'Creates QR code for user to scan it for auth app (like Google Authenticator)',
  })
  @Post('create-2fa-qrcode')
  async create2faQrCode(
    @Body() create2faQrCodeRequest: Create2faQrCodeRequest,
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
  @Post('enable-2fa')
  async enable2FA(
    @Body() enable2faRequest: Enable2faRequest,
  ): Promise<RecoveryKeysRespnse> {
    const recoveryKey = await this.authService.enable2fa(
      enable2faRequest.userId,
      enable2faRequest.token,
    );

    return RecoveryKeysRespnse.from(recoveryKey);
  }

  @HttpCode(200)
  @ApiOperation({ summary: 'Disables 2FA for logged user' })
  @Post('disable-2fa')
  async disable2fa(
    @Body() disable2faRequest: Disable2faRequest,
  ): Promise<void> {
    await this.authService.disable2fa(disable2faRequest.userId);
  }

  @HttpCode(200)
  @ApiOperation({ summary: 'Authenticate with 2FA to login' })
  @Post('verify-2fa')
  async verify2FA(
    @Body() verify2faRequest: Verify2faRequest,
  ): Promise<SignInResponse> {
    const accessToken = await this.authService.verify2fa(
      verify2faRequest.userId,
      verify2faRequest.token,
    );

    return SignInResponse.from(accessToken);
  }

  @HttpCode(201)
  @ApiOperation({ summary: 'Regenerate recovery keys for 2FA' })
  @Post('regenerate-2fa-recovery-keys')
  async regenerateRecoveryKeys(
    @Body() regenerateRecoveryKeysRequest: RegenerateRecoveryKeysRequest,
  ): Promise<RecoveryKeysRespnse> {
    const recoveryKeys = await this.authService.generate2faRecoveryKeys(
      regenerateRecoveryKeysRequest.userId,
    );

    return RecoveryKeysRespnse.from(recoveryKeys);
  }
}
