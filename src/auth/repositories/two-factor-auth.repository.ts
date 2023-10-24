import { Injectable } from '@nestjs/common';
import { TwoFactorAuth } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class TwoFactorAuthRepository {
  constructor(private readonly prismaService: PrismaService) {}

  save2faSecretKeyForUserWithId(
    userId: number,
    secretKey: string,
  ): Promise<TwoFactorAuth> {
    const dataObject = {
      data: {
        userId,
        secretKey,
      },
    };

    return this.prismaService.twoFactorAuth.create(dataObject);
  }
}
