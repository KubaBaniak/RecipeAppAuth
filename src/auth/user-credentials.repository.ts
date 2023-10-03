import { Injectable } from '@nestjs/common';
import { UserCredentials } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';

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

  getUserCredentialsByUserId(userId: number): Promise<{ password: string }> {
    const queryObject = {
      where: { userId },
      select: { password: true },
    };
    return this.prismaService.userCredentials.findUnique(queryObject);
  }
}
