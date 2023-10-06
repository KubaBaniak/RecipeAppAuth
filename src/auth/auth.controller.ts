import { Controller, Body, Post, HttpCode } from '@nestjs/common';
import { AuthService } from './auth.service';
import { ChangePasswordRequest, SignUpRequest, SignUpResponse } from './dto';
import {
  ApiTags,
  ApiBadRequestResponse,
  ApiOperation,
  ApiForbiddenResponse,
} from '@nestjs/swagger';

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
  @ApiOperation({ summary: 'Changes password of the user' })
  @Post('change-password')
  async changePassword(@Body() changePasswordRequest: ChangePasswordRequest) {
    await this.authService.changePassword(changePasswordRequest);
  }
}
