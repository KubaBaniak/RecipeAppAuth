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
import {
  MessageHandlerErrorBehavior,
  RabbitMQModule,
} from '@golevelup/nestjs-rabbitmq';
import { RABBITMQ_URL_ADDRESS } from './constants';

@Module({
  imports: [
    RabbitMQModule.forRoot(RabbitMQModule, {
      defaultSubscribeErrorBehavior: MessageHandlerErrorBehavior.NACK,
      defaultRpcErrorBehavior: MessageHandlerErrorBehavior.NACK,
      exchanges: [
        {
          name: 'authentication',
          type: 'topic',
        },
      ],
      uri: RABBITMQ_URL_ADDRESS,
      enableControllerDiscovery: true,
    }),
    AuthModule,
  ],
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
  exports: [RabbitMQModule],
})
export class AuthModule {}
