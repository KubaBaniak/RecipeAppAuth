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
  CreatePatRequest,
  CreatePatResponse,
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
}
