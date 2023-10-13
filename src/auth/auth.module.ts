import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PrismaService } from '../prisma/prisma.service';
import {
  UserCredentialsRepository,
  PersonalAccessTokenRepository,
} from './repositories';
import { JwtService } from '@nestjs/jwt';

@Module({
  controllers: [AuthController],
  providers: [
    AuthService,
    UserCredentialsRepository,
    PersonalAccessTokenRepository,
    JwtService,
    PrismaService,
  ],
  exports: [AuthService],
})
export class AuthModule {}
