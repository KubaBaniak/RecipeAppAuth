import { Injectable } from '@nestjs/common';
import { PendingUserCredentials } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class PendingUserCredentialsRepository {
  constructor(private readonly prismaService: PrismaService) {}

  async storePendingUserCredentials(
    userId: number,
    password: string,
  ): Promise<PendingUserCredentials> {
    const dataObject = {
      data: {
        userId,
        password,
      },
    };

    return this.prismaService.userCredentials.create(dataObject);
  }

  async getPendingUserCredentialsById(
    userId: number,
  ): Promise<PendingUserCredentials | null> {
    const queryObject = {
      where: { userId },
    };

    return this.prismaService.pendingUserCredentials.findUnique(queryObject);
  }

  async removePendingUserCredentialsById(
    userId: number,
  ): Promise<PendingUserCredentials> {
    const queryObject = {
      where: { userId },
    };

    return this.prismaService.pendingUserCredentials.delete(queryObject);
  }
}
