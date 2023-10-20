import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from '../auth.service';
import { faker } from '@faker-js/faker';
import {
  TwoFactorAuthRepository,
  UserCredentialsRepository,
} from '../repositories';
import * as bcrypt from 'bcryptjs';
import { BCRYPT, MAX_INT32, NUMBER_OF_2FA_RECOVERY_KEYS } from '../constants';
import { PrismaService } from '../../prisma/prisma.service';
import {
  MockTwoFactorAuthRepository,
  MockUserCredentialsRepository,
} from '../__mocks__';
import { JwtService } from '@nestjs/jwt';
import { authenticator } from 'otplib';
import { create2fa } from './twoFactorAuth.factory';

describe('AuthService', () => {
  let authService: AuthService;
  let userCredentialsRepository: UserCredentialsRepository;
  let twoFactorAuthRepository: TwoFactorAuthRepository;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        PrismaService,
        JwtService,
        {
          provide: UserCredentialsRepository,
          useClass: MockUserCredentialsRepository,
        },
        {
          provide: TwoFactorAuthRepository,
          useClass: MockTwoFactorAuthRepository,
        },
      ],
    }).compile();

    authService = module.get<AuthService>(AuthService);
    userCredentialsRepository = module.get<UserCredentialsRepository>(
      UserCredentialsRepository,
    );
    twoFactorAuthRepository = module.get<TwoFactorAuthRepository>(
      TwoFactorAuthRepository,
    );
  });

  afterAll(async () => {
    jest.clearAllMocks();
  });

  describe('SignUp', () => {
    it('should sign up user', async () => {
      //given
      const request = {
        userId: faker.number.int({ max: MAX_INT32 }),
        password: faker.internet.password(),
      };
      jest
        .spyOn(userCredentialsRepository, 'getUserCredentialsByUserId')
        .mockImplementationOnce(() => Promise.resolve(null));

      //when
      const userCredentials = await authService.signUp(request);

      //then
      expect(typeof userCredentials).toEqual('number');
      expect(userCredentials).toEqual(request.userId);
    });
  });

  describe('SignIn', () => {
    it('should return access token', async () => {
      const request = {
        userId: faker.number.int({ max: MAX_INT32 }),
        password: await bcrypt.hash(
          faker.internet.password({ length: 64 }),
          BCRYPT.SALT,
        ),
      };
      jest
        .spyOn(userCredentialsRepository, 'getUserCredentialsByUserId')
        .mockImplementationOnce(() => Promise.resolve(request));

      //when
      const accessToken = await authService.signIn(request);

      //then
      expect(accessToken).toBeDefined();
      expect(typeof accessToken).toBe('string');
    });
  });

  describe('Two factor authentication', () => {
    it('should create QR code with secret Key', async () => {
      const userId = faker.number.int({ max: MAX_INT32 });

      const qrCode = await authService.createQrCodeFor2fa(userId);

      expect(qrCode).toBeDefined();
      expect(typeof qrCode).toBe('string');
    });

    it('should enable 2fa', async () => {
      const twoFactorAuthSecret = authenticator.generateSecret();
      const userId = faker.number.int({ max: MAX_INT32 });
      const providedToken = authenticator.generate(twoFactorAuthSecret);
      jest
        .spyOn(twoFactorAuthRepository, 'get2faForUserWithId')
        .mockResolvedValueOnce(
          create2fa({
            userId,
            secretKey: twoFactorAuthSecret,
            isEnabled: false,
          }),
        );

      const recoveryKeys = await authService.enable2fa(userId, providedToken);

      expect(recoveryKeys).toBeDefined();
      expect(recoveryKeys).toBeInstanceOf(Array<string>);
      expect(recoveryKeys).toHaveLength(NUMBER_OF_2FA_RECOVERY_KEYS);
    });

    it('should disable 2fa', async () => {
      const userId = faker.number.int({ max: MAX_INT32 });
      jest
        .spyOn(twoFactorAuthRepository, 'get2faForUserWithId')
        .mockResolvedValueOnce(create2fa({ userId, isEnabled: true }));

      await authService.disable2fa(userId);

      expect(twoFactorAuthRepository.get2faForUserWithId).toHaveBeenCalled();
      expect(
        twoFactorAuthRepository.disable2faForUserWithId,
      ).toHaveBeenCalled();
    });
  });
});
