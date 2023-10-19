import { Controller, Body, Post, HttpCode, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import {
  Create2faQrCodeRequest,
  Create2faQrCodeResponse,
  SignInRequest,
  SignInResponse,
  SignUpRequest,
  SignUpResponse,
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
}
