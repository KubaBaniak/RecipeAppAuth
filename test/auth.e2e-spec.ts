import request from 'supertest';
import { Test } from '@nestjs/testing';
import { AuthModule } from '../src/auth/auth.module';
import { AuthService } from '../src/auth/auth.service';
import { HttpStatus, INestApplication, ValidationPipe } from '@nestjs/common';
import { PrismaService } from '../src/prisma/prisma.service';
import {
  PersonalAccessTokenRepository,
  UserCredentialsRepository,
} from '../src/auth/repositories';
import { generateUserCredentials } from '../src/auth/test/user-credentials.factory';
import { faker } from '@faker-js/faker';
import { MAX_INT32 } from '../src/auth/constants';
import { JwtService } from '@nestjs/jwt';

describe('AuthController (e2e)', () => {
  let app: INestApplication;
  let prismaService: PrismaService;

  beforeEach(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AuthModule],
      providers: [
        AuthService,
        JwtService,
        UserCredentialsRepository,
        PersonalAccessTokenRepository,
        PrismaService,
      ],
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
    await prismaService.$disconnect();
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

  describe('POST /auth/create-pat', () => {
    it(`should create personal access token for user`, async () => {
      const patCreateRequest = { userId: faker.number.int({ max: MAX_INT32 }) };
      return request(app.getHttpServer())
        .post('/auth/create-pat')
        .set('Accept', 'application/json')
        .send(patCreateRequest)
        .expect(async () => {
          const { userId } = patCreateRequest;
          const pat = await prismaService.personalAccessTokens.findUnique({
            where: { userId },
          });
          expect(pat).toBeDefined();
          expect(pat).toEqual(
            expect.objectContaining({
              userId,
              createdAt: expect.any(Date),
              token: expect.any(String),
              invalidatedAt: null,
            }),
          );
        })
        .expect(HttpStatus.CREATED);
    });
  });
});
