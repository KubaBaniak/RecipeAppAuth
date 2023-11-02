import { Test } from '@nestjs/testing';
import { AuthModule } from '../src/auth/auth.module';
import { AuthService } from '../src/auth/auth.service';
import { INestApplication, ValidationPipe } from '@nestjs/common';
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
import { AmqpConnection } from '@golevelup/nestjs-rabbitmq';
import { mock } from 'jest-mock-extended';

describe('AuthController (e2e)', () => {
  let app: INestApplication;
  let prismaService: PrismaService;
  let jwtServcie: JwtService;
  let amqpConnection: AmqpConnection;

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
        { provide: AmqpConnection, useValue: mock<AmqpConnection>() },
      ],
    }).compile();
    jest.clearAllMocks();

    app = moduleRef.createNestApplication();
    prismaService = moduleRef.get<PrismaService>(PrismaService);
    jwtServcie = moduleRef.get<JwtService>(JwtService);
    amqpConnection = moduleRef.get<AmqpConnection>(AmqpConnection);

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

  describe('authentication signup', () => {
    it(`should save user's credentials`, async () => {
      const userCredentials = generateUserCredentials();
      const { accountActivationToken } = await amqpConnection.request<{
        accountActivationToken: string;
      }>({
        exchange: 'authentication',
        routingKey: 'signup',
        payload: userCredentials,
      });
      const credentials = await prismaService.pendingUserCredentials.findUnique(
        {
          where: { userId: userCredentials.userId },
        },
      );
      expect(credentials).toBeDefined();
      expect(credentials?.userId).toBeDefined();
      expect(typeof credentials?.userId).toBe('number');
      expect(typeof accountActivationToken).toBe('string');
    });

    it(`should not save user's credentials (already in db) and return 403 error`, async () => {
      const userCredentials = generateUserCredentials();
      await prismaService.userCredentials.create({
        data: userCredentials,
      });
      const errorResponse = await amqpConnection.request<{
        message: string;
        status: number;
      }>({
        exchange: 'authentication',
        routingKey: 'signup',
        payload: userCredentials,
      });
      expect(typeof errorResponse.message).toBe('string');
      expect(errorResponse.status).toBe(403);
    });
  });

  describe('authentication signin', () => {
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
      const { accessToken } = await amqpConnection.request<{
        accessToken: string;
      }>({
        exchange: 'authentication',
        routingKey: 'signin',
        payload: userCredentials,
      });
      expect(typeof accessToken).toBe('string');
    });

    it(`should throw 401 - user does not exist`, async () => {
      const userCredentials = generateUserCredentials();
      await prismaService.userCredentials.create({ data: userCredentials });
      const errorResponse = await amqpConnection.request<{
        message: string;
        status: number;
      }>({
        exchange: 'authentication',
        routingKey: 'signin',
        payload: {
          userId: faker.number.int({ max: MAX_INT32 }),
          password: userCredentials.password,
        },
      });

      expect(errorResponse.status).toBe(401);
      expect(typeof errorResponse.message).toBe('string');
    });
  });

  describe('authentication validate-user', () => {
    it('should validate user credentials', async () => {
      const password = faker.internet.password({ length: 64 });
      const userCredentials = await generateUserCredentialsWithHashedPassword({
        password,
      });
      await prismaService.userCredentials.create({ data: userCredentials });

      const validatedUserId = await amqpConnection.request<{
        validatedUserId: number;
      }>({
        exchange: 'authentication',
        routingKey: 'validate-user',
        payload: {
          userId: userCredentials.userId,
          password: password,
        },
      });
      expect(validatedUserId).toEqual(userCredentials.userId);
    });

    it('should not validate user (wrong credentials)', async () => {
      const userCredentials = await generateUserCredentialsWithHashedPassword();
      await prismaService.userCredentials.create({ data: userCredentials });

      const errorResponse = await amqpConnection.request<{
        message: string;
        status: number;
      }>({
        exchange: 'authentication',
        routingKey: 'validate-user',
        payload: {
          userId: userCredentials.userId,
          password: faker.internet.password({ length: 64 }),
        },
      });
      expect(errorResponse.status).toBe(401);
      expect(typeof errorResponse.message).toBe('string');
    });
  });

  describe('authentication validate-jwt-token', () => {
    it('should validate JWT', async () => {
      const userId = faker.number.int({ max: MAX_INT32 });
      const token = jwtServcie.sign(
        { id: userId },
        { secret: AUTH.AUTH_TOKEN },
      );

      const tokenPayload = await amqpConnection.request<number>({
        exchange: 'authentication',
        routingKey: 'validate-jwt-token',
        payload: {
          token,
        },
      });

      expect(tokenPayload).toEqual(userId);
    });

    it('should not validate JWT (invalid token)', async () => {
      const token = faker.string.alphanumeric({ length: 64 });

      const errorResponse = await amqpConnection.request<{
        message: string;
        status: number;
      }>({
        exchange: 'authentication',
        routingKey: 'validate-jwt-token',
        payload: {
          token,
        },
      });

      expect(errorResponse.status).toBe(401);
      expect(typeof errorResponse.message).toBe('string');
    });
  });

  describe('authentication generate-password-reset-token', () => {
    it('should generate token for password reset', async () => {
      const userCredentials = generateUserCredentials();
      await prismaService.userCredentials.create({ data: userCredentials });

      const token = await amqpConnection.request<string>({
        exchange: 'authentication',
        routingKey: 'generate-password-reset-token',
        payload: {
          userId: userCredentials.userId,
        },
      });

      const tokenPayload = jwtServcie.verify(token, {
        secret: AUTH.PASSWORD_RESET,
      });
      expect(userCredentials.userId).toEqual(tokenPayload.id);
    });
    it('should not generate token for password reset', async () => {
      const token = await amqpConnection.request<string>({
        exchange: 'authentication',
        routingKey: 'generate-password-reset-token',
        payload: {
          userId: faker.number.int({ max: MAX_INT32 }),
        },
      });

      expect(token).toEqual('');
    });
  });

  describe('authentication add-personal-access-token', () => {
    it(`should create personal access token for user`, async () => {
      const userId = faker.number.int({ max: MAX_INT32 });
      const patCreateRequest = { userId };
      const { personalAccessToken } = await amqpConnection.request<{
        personalAccessToken: string;
      }>({
        exchange: 'authentication',
        routingKey: 'add-personal-access-token',
        payload: patCreateRequest,
      });
      expect(typeof personalAccessToken).toBe('string');
      const pat = await prismaService.personalAccessTokens.findUnique({
        where: { userId },
      });
      expect(pat).toEqual(
        expect.objectContaining({
          userId,
          createdAt: expect.any(Date),
          token: expect.any(String),
          invalidatedAt: null,
        }),
      );
    });
  });

  describe('authentication change-password', () => {
    it(`should change password`, async () => {
      const userCredentials = await generateUserCredentialsWithHashedPassword();
      await prismaService.userCredentials.create({ data: userCredentials });
      const newPassword = faker.internet.password({ length: 64 });

      const changedPasswordUserId = await amqpConnection.request<number>({
        exchange: 'authentication',
        routingKey: 'change-password',
        payload: { userId: userCredentials.userId, newPassword },
      });

      expect(changedPasswordUserId).toEqual(userCredentials.userId);

      const result = await prismaService.userCredentials.findUnique({
        where: { userId: changedPasswordUserId },
      });
      if (result?.password) {
        const passwordsMatch = await bcrypt.compare(
          newPassword,
          result.password,
        );
        expect(passwordsMatch).toBe(true);
      }
    });
  });

  describe('authentication activate-account', () => {
    it(`should activate account`, async () => {
      const userCredentials = await generateUserCredentialsWithHashedPassword();
      await prismaService.pendingUserCredentials.create({
        data: userCredentials,
      });
      const token = jwtServcie.sign(
        { id: userCredentials.userId },
        {
          secret: AUTH.ACCOUNT_ACTIVATION,
        },
      );
      const userId = await amqpConnection.request<number>({
        exchange: 'authentication',
        routingKey: 'activate-account',
        payload: { token },
      });
      const savedUserCredentials =
        await prismaService.userCredentials.findFirst({
          where: { userId },
        });
      const pendingUserCredentials =
        await prismaService.pendingUserCredentials.findFirst({
          where: { userId },
        });
      expect(savedUserCredentials).toBeDefined();
      expect(pendingUserCredentials).toBeNull();
    });
  });

  describe('authentication create-2fa-qrcode', () => {
    it('should create QR code', async () => {
      const userId = faker.number.int({ max: MAX_INT32 });
      const { qrCodeUrl } = await amqpConnection.request<{ qrCodeUrl: string }>(
        {
          exchange: 'authentication',
          routingKey: 'create-2fa-qrcode',
          payload: { userId },
        },
      );
      expect(qrCodeUrl).toBeDefined();
      expect(typeof qrCodeUrl).toBe('string');
    });
  });

  describe('authentication enable-2fa', () => {
    it('should enable 2fa', async () => {
      const twoFactorAuth = await prismaService.twoFactorAuth.create({
        data: create2fa(),
      });
      const { recoveryKeys } = await amqpConnection.request<{
        recoveryKeys: string[];
      }>({
        exchange: 'authentication',
        routingKey: 'enable-2fa',
        payload: {
          userId: twoFactorAuth.userId,
          token: authenticator.generate(twoFactorAuth.secretKey),
        },
      });
      const enabled2fa = await prismaService.twoFactorAuth.findUnique({
        where: {
          userId: twoFactorAuth.userId,
        },
      });
      expect(recoveryKeys).toBeInstanceOf(Array<string>);
      expect(recoveryKeys).toHaveLength(NUMBER_OF_2FA_RECOVERY_KEYS);
      expect(enabled2fa?.isEnabled).toEqual(true);
    });
  });

  describe('authentication disable-2fa', () => {
    it('should disable 2fa', async () => {
      const twoFactorAuth = await prismaService.twoFactorAuth.create({
        data: create2fa({ isEnabled: true }),
      });
      const twoFactorAuthUserId = await amqpConnection.request<{
        twoFactorAuthUserId: number;
      }>({
        exchange: 'authentication',
        routingKey: 'disable-2fa',
        payload: {
          userId: twoFactorAuth.userId,
        },
      });
      const enabled2fa = await prismaService.twoFactorAuth.findUnique({
        where: {
          userId: twoFactorAuth.userId,
        },
      });
      expect(enabled2fa?.userId).toEqual(twoFactorAuthUserId);
      expect(enabled2fa?.isEnabled).toEqual(false);
    });
  });

  describe('authentication verify-2fa', () => {
    it('should verify normal 2fa token', async () => {
      const secret2fa = authenticator.generateSecret();
      const userId = faker.number.int({ max: MAX_INT32 });
      const twoFactorAuth = await prismaService.twoFactorAuth.create({
        data: create2fa({ isEnabled: true, secretKey: secret2fa, userId }),
      });
      const { accessToken } = await amqpConnection.request<{
        accessToken: string;
      }>({
        exchange: 'authentication',
        routingKey: 'verify-2fa',
        payload: {
          userId: twoFactorAuth.userId,
          token: authenticator.generate(secret2fa),
        },
      });
      expect(accessToken).toBeDefined();
      expect(typeof accessToken).toBe('string');
    });

    it('should verify 2fa recovery token', async () => {
      const secret2fa = authenticator.generateSecret();
      const userId = faker.number.int({ max: MAX_INT32 });
      await prismaService.twoFactorAuth.create({
        data: create2fa({ isEnabled: true, secretKey: secret2fa, userId }),
      });
      await prismaService.twoFactorAuthRecoveryKey.createMany({
        data: createRecoveryKeys({
          twoFactorAuthUserId: userId,
        }),
      });
      const recoveryKey =
        await prismaService.twoFactorAuthRecoveryKey.findFirst({
          where: { twoFactorAuthUserId: userId },
        });
      const { accessToken } = await amqpConnection.request<{
        accessToken: string;
      }>({
        exchange: 'authentication',
        routingKey: 'verify-2fa',
        payload: {
          userId: userId,
          token: recoveryKey?.key,
        },
      });
      expect(accessToken).toBeDefined();
      expect(typeof accessToken).toBe('string');
    });
  });

  describe('authentication regenerate-2fa-recovery-keys', () => {
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
      const { recoveryKeys } = await amqpConnection.request<{
        recoveryKeys: string[];
      }>({
        exchange: 'authentication',
        routingKey: 'regenerate-2fa-recovery-keys',
        payload: {
          userId: twoFactorAuth.userId,
        },
      });
      expect(recoveryKeys).toBeInstanceOf(Array<string>);
      expect(recoveryKeys).toHaveLength(NUMBER_OF_2FA_RECOVERY_KEYS);
    });
  });
});
