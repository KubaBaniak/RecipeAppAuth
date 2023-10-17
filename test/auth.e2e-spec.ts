import request from 'supertest';
import { Test } from '@nestjs/testing';
import { AuthModule } from '../src/auth/auth.module';
import { AuthService } from '../src/auth/auth.service';
import { HttpStatus, INestApplication, ValidationPipe } from '@nestjs/common';
import { PrismaService } from '../src/prisma/prisma.service';
import {
  PendingUserCredentialsRepository,
  UserCredentialsRepository,
} from '../src/auth/repositories';
import { generateUserCredentials } from '../src/auth/test/user-credentials.factory';
import { faker } from '@faker-js/faker';
import * as bcrypt from 'bcryptjs';
import { BCRYPT, SECRETS } from '../src/auth/constants';
import { JwtService } from '@nestjs/jwt';

describe('AuthController (e2e)', () => {
  let app: INestApplication;
  let prismaService: PrismaService;
  let jwtServcie: JwtService;

  beforeEach(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AuthModule],
      providers: [
        JwtService,
        AuthService,
        UserCredentialsRepository,
        PendingUserCredentialsRepository,
        PrismaService,
      ],
    }).compile();

    app = moduleRef.createNestApplication();
    prismaService = moduleRef.get<PrismaService>(PrismaService);
    jwtServcie = moduleRef.get<JwtService>(JwtService);

    app.useGlobalPipes(new ValidationPipe());

    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        transform: true,
      }),
    );
    await prismaService.userCredentials.deleteMany();
    await prismaService.pendingUserCredentials.deleteMany();
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
          const credentials =
            await prismaService.pendingUserCredentials.findUnique({
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
      await prismaService.userCredentials.create({
        data: userCredentials,
      });
      return request(app.getHttpServer())
        .post('/auth/signup')
        .set('Accept', 'application/json')
        .send(userCredentials)
        .expect(HttpStatus.CONFLICT);
    });
  });

  describe('POST /auth/signin', () => {
    it(`should return access token`, async () => {
      const userCredentials = generateUserCredentials();
      const hashedPassword = await bcrypt.hash(
        userCredentials.password,
        BCRYPT.SALT,
      );
      await prismaService.userCredentials.create({
        data: {
          userId: userCredentials.userId,
          password: hashedPassword,
        },
      });
      return request(app.getHttpServer())
        .post('/auth/signin')
        .set('Accept', 'application/json')
        .send(userCredentials)
        .expect((response: request.Response) => {
          expect(response.body.accessToken).toBeDefined();
          expect(typeof response.body.accessToken).toBe('string');
        })
        .expect(HttpStatus.OK);
    });

    it(`should throw 401 - wrong password`, async () => {
      const userCredentials = generateUserCredentials();
      await prismaService.userCredentials.create({ data: userCredentials });
      return request(app.getHttpServer())
        .post('/auth/signin')
        .set('Accept', 'application/json')
        .send({
          userId: userCredentials.userId,
          password: faker.internet.password({
            length: 64,
          }),
        })
        .expect(HttpStatus.UNAUTHORIZED);
    });
    it(`should throw 401 - user does not exist`, async () => {
      return request(app.getHttpServer())
        .post('/auth/signin')
        .set('Accept', 'application/json')
        .send(generateUserCredentials())
        .expect(HttpStatus.UNAUTHORIZED);
    });
  });

  describe('GET /auth/activate-account', () => {
    it(`should activate account`, async () => {
      const userCredentials = generateUserCredentials();
      const hashedPassword = await bcrypt.hash(
        userCredentials.password,
        BCRYPT.SALT,
      );
      const { userId } = await prismaService.pendingUserCredentials.create({
        data: {
          userId: userCredentials.userId,
          password: hashedPassword,
        },
      });
      const token = jwtServcie.sign(
        { id: userId },
        {
          secret: SECRETS.ACCOUNT_ACTIVATION,
        },
      );
      return request(app.getHttpServer())
        .get(`/auth/activate-account/?token=${token}`)
        .set('Accept', 'application/json')
        .expect(async () => {
          const userCredentials = await prismaService.userCredentials.findFirst(
            {
              where: { userId },
            },
          );
          const pendingUserCredentials =
            await prismaService.pendingUserCredentials.findFirst({
              where: { userId },
            });
          expect(userCredentials).toBeDefined();
          expect(pendingUserCredentials).toBeNull();
        })
        .expect(HttpStatus.OK);
    });
  });
});
