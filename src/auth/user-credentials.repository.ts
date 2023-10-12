import { Injectable } from '@nestjs/common';
import { UserCredentials } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';

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

  async getUserCredentialsByUserId(userId: number): Promise<string | null> {
    const queryObject = {
      select: { password: true },
      where: { userId },
    };

    const result = await this.prismaService.userCredentials.findUnique(
      queryObject,
    );

    return result ? result.password : null;
  }
}
