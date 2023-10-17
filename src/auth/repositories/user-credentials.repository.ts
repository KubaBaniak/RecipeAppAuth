import { Injectable } from '@nestjs/common';
import { UserCredentials } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class UserCredentialsRepository {
  constructor(private readonly prismaService: PrismaService) {}

  async storeUserCredentials(
    userId: number,
    password: string,
  ): Promise<UserCredentials> {
    const dataObject = {
      data: {
        userId,
        password,
      },
    };

    return this.prismaService.userCredentials.create(dataObject);
  }

  async getUserCredentialsByUserId(
    userId: number,
  ): Promise<UserCredentials | null> {
    const queryObject = {
      where: { userId },
    };

    return this.prismaService.userCredentials.findUnique(queryObject);
  }
}
