import { Injectable } from '@nestjs/common';
import { UserCredentials } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class UserCredentialsRepository {
  constructor(private readonly prismaService: PrismaService) {}

  storeUserCredentials(
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

  getUserCredentialsByUserId(
    userId: number,
  ): Promise<{ password: string } | null> {
    const queryObject = {
      select: { password: true },
      where: { userId },
    };
    return this.prismaService.userCredentials.findUnique(queryObject);
  }
}
