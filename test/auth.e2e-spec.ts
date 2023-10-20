import request from 'supertest';
import { Test } from '@nestjs/testing';
import { AuthModule } from '../src/auth/auth.module';
import { AuthService } from '../src/auth/auth.service';
import { HttpStatus, INestApplication, ValidationPipe } from '@nestjs/common';
import { PrismaService } from '../src/prisma/prisma.service';
import {
  UserCredentialsRepository,
  TwoFactorAuthRepository,
} from '../src/auth/repositories';
import { generateUserCredentials } from '../src/auth/test/user-credentials.factory';
import { faker } from '@faker-js/faker';
import * as bcrypt from 'bcryptjs';
import { BCRYPT, MAX_INT32 } from '../src/auth/constants';
import { JwtService } from '@nestjs/jwt';
import { authenticator } from 'otplib';
import { create2fa } from '../src/auth/test/twoFactorAuth.factory';

describe('AuthController (e2e)', () => {
  let app: INestApplication;
  let prismaService: PrismaService;

  beforeEach(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AuthModule],
      providers: [
        JwtService,
        AuthService,
        UserCredentialsRepository,
        TwoFactorAuthRepository,
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

  describe('POST auth/create-2fa-qrcode', () => {
    it('should create QR code', () => {
      const userId = faker.number.int({ max: MAX_INT32 });
      return request(app.getHttpServer())
        .post('/auth/create-2fa-qrcode')
        .set('Accept', 'application/json')
        .send({ userId })
        .expect((response: request.Response) => {
          expect(response.body).toBeDefined();
          expect(typeof response.body.urlToEnable2FA).toBe('string');
          expect(typeof response.body.qrCodeUrl).toBe('string');
        })
        .expect(HttpStatus.CREATED);
    });
    it('should enable 2fa', async () => {
      const twoFactorAuth = await prismaService.twoFactorAuth.create({
        data: create2fa(),
      });
      return request(app.getHttpServer())
        .post('/auth/enable-2fa')
        .set('Accept', 'application/json')
        .send({
          userId: twoFactorAuth.userId,
          token: authenticator.generate(twoFactorAuth.secretKey),
        })
        .expect(async () => {
          const enabled2fa = await prismaService.twoFactorAuth.findUnique({
            where: {
              userId: twoFactorAuth.userId,
            },
          });
          expect(enabled2fa?.isEnabled).toEqual(true);
        })
        .expect(HttpStatus.OK);
    });
    it('should disable 2fa', async () => {
      const twoFactorAuth = await prismaService.twoFactorAuth.create({
        data: create2fa({ isEnabled: true }),
      });
      return request(app.getHttpServer())
        .post('/auth/disable-2fa')
        .set('Accept', 'application/json')
        .send({
          userId: twoFactorAuth.userId,
        })
        .expect(async () => {
          const enabled2fa = await prismaService.twoFactorAuth.findUnique({
            where: {
              userId: twoFactorAuth.userId,
            },
          });
          expect(enabled2fa?.isEnabled).toEqual(false);
        })
        .expect(HttpStatus.OK);
    });
  });
});
