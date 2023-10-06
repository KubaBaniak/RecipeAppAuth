import request from 'supertest';
import { Test } from '@nestjs/testing';
import { AuthModule } from '../src/auth/auth.module';
import { AuthService } from '../src/auth/auth.service';
import { HttpStatus, INestApplication, ValidationPipe } from '@nestjs/common';
import { PrismaService } from '../src/prisma/prisma.service';
import { UserCredentialsRepository } from '../src/auth/repositories';
import {
  generateUserCredentials,
  generateUserCredentialsWithHashedPassword,
} from '../src/auth/test/user-credentials.factory';
import { faker } from '@faker-js/faker';
import * as bcrypt from 'bcryptjs';

describe('AuthController (e2e)', () => {
  let app: INestApplication;
  let prismaService: PrismaService;

  beforeEach(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AuthModule],
      providers: [AuthService, UserCredentialsRepository, PrismaService],
    }).compile();

    app = moduleRef.createNestApplication();
    prismaService = moduleRef.get<PrismaService>(PrismaService);

    app.useGlobalPipes(new ValidationPipe());

    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        transform: true,
      }),
    );
    await prismaService.userCredentials.deleteMany();
    await app.init();
  });

  afterAll(async () => {
    await prismaService.userCredentials.deleteMany();
    await app.close();
  });

  describe('POST /auth/signup', () => {
    it(`should save user's credentials`, async () => {
      const userCredentials = generateUserCredentials();
      return request(app.getHttpServer())
        .post('/auth/signup')
        .set('Accept', 'application/json')
        .send(userCredentials)
        .expect(async () => {
          const credentials = await prismaService.userCredentials.findUnique({
            where: { userId: userCredentials.userId },
          });
          expect(credentials).toBeDefined();
          expect(credentials?.userId).toBeDefined();
          expect(typeof credentials?.userId).toBe('number');
        })
        .expect(HttpStatus.CREATED);
    });

    it(`should not save user's credentials (already in db) and return 409 error`, async () => {
      const userCredentials = generateUserCredentials();
      await prismaService.userCredentials.create({ data: userCredentials });
      return request(app.getHttpServer())
        .post('/auth/signup')
        .set('Accept', 'application/json')
        .send(userCredentials)
        .expect(HttpStatus.CONFLICT);
    });
  });

  describe('POST /auth/change-password', () => {
    it(`should change password`, async () => {
      const userCredentials = await generateUserCredentialsWithHashedPassword();
      await prismaService.userCredentials.create({ data: userCredentials });
      const newPassword = faker.internet.password({ length: 64 });
      return request(app.getHttpServer())
        .post('/auth/change-password')
        .set('Accept', 'application/json')
        .send({ userId: userCredentials.userId, newPassword })
        .expect(async () => {
          const result = await prismaService.userCredentials.findUnique({
            where: { userId: userCredentials.userId },
          });
          if (result && result.password) {
            const passwordsMatch = await bcrypt.compare(
              newPassword,
              result.password,
            );
            expect(passwordsMatch).toBe(true);
          }
        })
        .expect(HttpStatus.OK);
    });
  });
});
