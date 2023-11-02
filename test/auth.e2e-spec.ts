import request from 'supertest';
import { Test } from '@nestjs/testing';
import { AuthModule } from '../src/auth/auth.module';
import { AuthService } from '../src/auth/auth.service';
import { HttpStatus, INestApplication, ValidationPipe } from '@nestjs/common';
import { PrismaService } from '../src/prisma/prisma.service';
import {
  UserCredentialsRepository,
  TwoFactorAuthRepository,
  PendingUserCredentialsRepository,
  PersonalAccessTokenRepository,
} from '../src/auth/repositories';
import {
  generateUserCredentials,
  generateUserCredentialsWithHashedPassword,
} from '../src/auth/test/user-credentials.factory';
import { faker } from '@faker-js/faker';
import {
  MAX_INT32,
  BCRYPT,
  AUTH,
  NUMBER_OF_2FA_RECOVERY_KEYS,
} from '../src/auth/constants';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { authenticator } from 'otplib';
import {
  create2fa,
  createRecoveryKeys,
} from '../src/auth/test/twoFactorAuth.factory';

describe('AuthController (e2e)', () => {
  let app: INestApplication;
  let prismaService: PrismaService;
  let jwtServcie: JwtService;

  beforeEach(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AuthModule],
      providers: [
        AuthService,
        JwtService,
        UserCredentialsRepository,
        TwoFactorAuthRepository,
        PendingUserCredentialsRepository,
        PersonalAccessTokenRepository,
        PrismaService,
      ],
    }).compile();
    jest.clearAllMocks();

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
          if (result?.password) {
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
          secret: AUTH.ACCOUNT_ACTIVATION,
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
        });
    });
  });

  describe('POST auth/create-2fa-qrcode', () => {
    it('should create QR code', () => {
      const userId = faker.number.int({ max: MAX_INT32 });
      return request(app.getHttpServer())
        .post('/auth/create-2FA-qrcode')
        .set('Accept', 'application/json')
        .send({ userId })
        .expect((response: request.Response) => {
          expect(response.body).toBeDefined();
          expect(typeof response.body.urlToEnable2FA).toBe('string');
          expect(typeof response.body.qrCodeUrl).toBe('string');
        })
        .expect(HttpStatus.CREATED);
    });
  });

  describe('POST /auth/enable-2fa', () => {
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
  });

  describe('POST /auth/disable-2fa', () => {
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

  describe('POST /auth/verify-2fa', () => {
    it('should verify normal 2fa token', async () => {
      const secret2fa = authenticator.generateSecret();
      const userId = faker.number.int({ max: MAX_INT32 });
      const twoFactorAuth = await prismaService.twoFactorAuth.create({
        data: create2fa({ isEnabled: true, secretKey: secret2fa, userId }),
      });
      return request(app.getHttpServer())
        .post('/auth/verify-2fa')
        .set('Accept', 'application/json')
        .send({
          userId: twoFactorAuth.userId,
          token: authenticator.generate(secret2fa),
        })
        .expect((response: request.Response) => {
          expect(response.body.accessToken).toBeDefined();
          expect(typeof response.body.accessToken).toBe('string');
        })
        .expect(HttpStatus.OK);
    });

    it('should verify 2fa recovery token', async () => {
      const secret2fa = authenticator.generateSecret();
      const userId = faker.number.int({ max: MAX_INT32 });
      const twoFactorAuth = await prismaService.twoFactorAuth.create({
        data: create2fa({ isEnabled: true, secretKey: secret2fa, userId }),
      });
      await prismaService.twoFactorAuthRecoveryKey.createMany({
        data: createRecoveryKeys({
          twoFactorAuthUserId: twoFactorAuth.userId,
        }),
      });
      const recoveryKey =
        await prismaService.twoFactorAuthRecoveryKey.findFirst({
          where: { twoFactorAuthUserId: userId },
        });
      return request(app.getHttpServer())
        .post('/auth/verify-2fa')
        .set('Accept', 'application/json')
        .send({
          userId: twoFactorAuth.userId,
          token: recoveryKey?.key,
        })
        .expect((response: request.Response) => {
          expect(response.body.accessToken).toBeDefined();
          expect(typeof response.body.accessToken).toBe('string');
        })
        .expect(HttpStatus.OK);
    });
  });

  describe('POST /auth/regenerate-2fa-recovery-keys', () => {
    it('should regenerate recovery keys for 2FA', async () => {
      const secret2fa = authenticator.generateSecret();
      const userId = faker.number.int({ max: MAX_INT32 });
      const twoFactorAuth = await prismaService.twoFactorAuth.create({
        data: create2fa({ isEnabled: true, secretKey: secret2fa, userId }),
      });
      await prismaService.twoFactorAuthRecoveryKey.createMany({
        data: createRecoveryKeys({
          twoFactorAuthUserId: twoFactorAuth.userId,
        }),
      });
      return request(app.getHttpServer())
        .post('/auth/regenerate-2fa-recovery-keys')
        .set('Accept', 'application/json')
        .send({
          userId: twoFactorAuth.userId,
        })
        .expect((response: request.Response) => {
          const { recoveryKeys }: { recoveryKeys: string[] } = response.body;
          expect(recoveryKeys).toBeInstanceOf(Array<string>);
          expect(recoveryKeys).toHaveLength(NUMBER_OF_2FA_RECOVERY_KEYS);
        })
        .expect(HttpStatus.CREATED);
    });
  });
});
