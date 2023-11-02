import { Injectable } from '@nestjs/common';
import { TwoFactorAuth, TwoFactorAuthRecoveryKey } from '@prisma/client';
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

  get2faForUserWithId(userId: number): Promise<TwoFactorAuth | null> {
    const queryObject = {
      where: {
        userId,
      },
    };

    return this.prismaService.twoFactorAuth.findUnique(queryObject);
  }

  enable2faForUserWithId(userId: number): Promise<TwoFactorAuth> {
    const queryObject = {
      where: {
        userId,
      },
      data: {
        isEnabled: true,
      },
    };

    return this.prismaService.twoFactorAuth.update(queryObject);
  }

  disable2faForUserWithId(userId: number): Promise<TwoFactorAuth> {
    const queryObject = {
      where: {
        userId,
      },
      data: {
        isEnabled: false,
      },
    };

    return this.prismaService.twoFactorAuth.update(queryObject);
  }

  async saveRecoveryKeysForUserWithId(
    userId: number,
    recoveryKeys: { key: string }[],
  ): Promise<void> {
    for await (const { key } of recoveryKeys) {
      this.prismaService.twoFactorAuthRecoveryKey.create({
        data: {
          twoFactorAuthUserId: userId,
          key,
        },
      });
    }
  }

  getRecoveryKeysForUserWithId(
    userId: number,
  ): Promise<{ key: string; isUsed: boolean }[] | null> {
    return this.prismaService.twoFactorAuthRecoveryKey.findMany({
      where: {
        twoFactorAuthUserId: userId,
      },
      select: {
        key: true,
        isUsed: true,
      },
    });
  }

  expire2faRecoveryKey(key: string): Promise<TwoFactorAuthRecoveryKey> {
    return this.prismaService.twoFactorAuthRecoveryKey.update({
      data: {
        isUsed: true,
        usedAt: new Date(),
      },
      where: {
        key,
      },
    });
  }
}
