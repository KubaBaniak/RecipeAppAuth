import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PrismaService } from '../prisma/prisma.service';
import {
  UserCredentialsRepository,
  TwoFactorAuthRepository,
} from './repositories';
import { LocalAuthGuard } from './guards';
import { LocalStrategy } from './strategies';
import { JwtService } from '@nestjs/jwt';

@Module({
  providers: [
    AuthService,
    JwtService,
    UserCredentialsRepository,
    TwoFactorAuthRepository,
    PrismaService,
    LocalStrategy,
    LocalAuthGuard,
  ],
  controllers: [AuthController],
  exports: [AuthService],
})
export class AuthModule {}
