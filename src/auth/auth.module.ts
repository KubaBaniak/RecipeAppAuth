import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PrismaService } from '../prisma/prisma.service';
import { UserCredentialsRepository } from './repositories';

@Module({
  controllers: [AuthController],
  providers: [AuthService, UserCredentialsRepository, PrismaService],
  exports: [AuthService],
})
export class AuthModule {}
