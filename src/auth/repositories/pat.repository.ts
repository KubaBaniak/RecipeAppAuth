import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { PersonalAccessTokens } from '@prisma/client';

@Injectable()
export class PersonalAccessTokenRepository {
  constructor(private prisma: PrismaService) {}

  savePersonalAccessToken(
    userId: number,
    token: string,
  ): Promise<PersonalAccessTokens> {
    return this.prisma.personalAccessTokens.create({
      data: {
        token,
        userId: userId,
      },
    });
  }

  getValidPatForUserId(userId: number): Promise<PersonalAccessTokens | null> {
    return this.prisma.personalAccessTokens.findFirst({
      where: {
        userId,
        invalidatedAt: {
          equals: null,
        },
      },
    });
  }

  async invalidatePatForUserId(userId: number): Promise<void> {
    await this.prisma.personalAccessTokens.updateMany({
      where: {
        userId,
      },
      data: {
        invalidatedAt: new Date(),
      },
    });
  }
}
