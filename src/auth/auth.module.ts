import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PrismaService } from '../prisma/prisma.service';
import {
  UserCredentialsRepository,
  TwoFactorAuthRepository,
  PendingUserCredentialsRepository,
  PersonalAccessTokenRepository,
} from './repositories';
import { JwtService } from '@nestjs/jwt';

@Module({
  providers: [
    AuthService,
    JwtService,
    UserCredentialsRepository,
    TwoFactorAuthRepository,
    PendingUserCredentialsRepository,
    PersonalAccessTokenRepository,
    PrismaService,
  ],
  controllers: [AuthController],
  exports: [AuthService],
})
export class AuthModule {}
