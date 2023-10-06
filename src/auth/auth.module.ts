import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PrismaService } from '../prisma/prisma.service';
import { UserCredentialsRepository } from './user-credentials.repository';
import { JwtModule } from '@nestjs/jwt';
import { JwtAuthGuard, LocalAuthGuard } from './guards';
import { PassportModule } from '@nestjs/passport';
import { LocalStrategy, UserAuthBearerStrategy } from './strategies';

@Module({
  imports: [PassportModule, JwtModule.register({ global: true })],
  providers: [
    AuthService,
    UserCredentialsRepository,
    PrismaService,
    LocalStrategy,
    UserAuthBearerStrategy,
    LocalAuthGuard,
    JwtAuthGuard,
  ],
  controllers: [AuthController],
  exports: [AuthService],
})
export class AuthModule {}
