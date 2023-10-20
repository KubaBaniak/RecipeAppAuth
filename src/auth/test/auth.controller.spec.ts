import { AuthController } from '../auth.controller';
import { AuthService } from '../auth.service';
import { MockAuthService } from '../__mocks__/auth.service.mock';
import { Test, TestingModule } from '@nestjs/testing';
import { faker } from '@faker-js/faker';
import { MAX_INT32, NUMBER_OF_2FA_RECOVERY_KEYS } from '../constants';
import {
  TwoFactorAuthRepository,
  UserCredentialsRepository,
} from '../repositories';
import { PrismaService } from '../../prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { authenticator } from 'otplib';

describe('AuthController', () => {
  let authController: AuthController;
  let authServcie: AuthService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        JwtService,
        UserCredentialsRepository,
        TwoFactorAuthRepository,
        PrismaService,
        JwtService,
        {
          provide: AuthService,
          useClass: MockAuthService,
        },
      ],
    }).compile();

    authController = module.get<AuthController>(AuthController);
    authServcie = module.get<AuthService>(AuthService);
  });

  describe('SignUp', () => {
    it('should sign up user', async () => {
      //given
      const request = {
        userId: faker.number.int({ max: MAX_INT32 }),
        password: faker.internet.password(),
      };

      //when
      const signedUpUser = await authController.signUp(request);

      //then
      expect(signedUpUser.userId).toEqual(request.userId);
    });
  });

  describe('SignIn', () => {
    it('should sign in / authenticate user', async () => {
      //given
      const request = {
        userId: faker.number.int(),
        password: faker.internet.password({ length: 64 }),
      };

      //when
      const { accessToken } = await authController.signIn(request);

      //then
      expect(accessToken).toBeDefined();
      expect(typeof accessToken).toBe('string');
    });
  });

  describe('Two factor authentication', () => {
    it('should create qrcode for 2fa', async () => {
      const request = {
        userId: faker.number.int({ max: MAX_INT32 }),
      };

      const qrCodeObject = await authController.create2faQrCode(request);

      //then
      expect(qrCodeObject).toBeDefined();
      expect(typeof qrCodeObject.qrCodeUrl).toBe('string');
      expect(typeof qrCodeObject.urlToEnable2FA).toBe('string');
    });

    it('should enable 2fa', async () => {
      const request = {
        userId: faker.number.int({ max: MAX_INT32 }),
        token: faker.string.alphanumeric({ length: 64 }),
      };

      const { recoveryKeys } = await authController.enable2FA(request);

      expect(recoveryKeys).toBeDefined();
      expect(recoveryKeys).toBeInstanceOf(Array<string>);
      expect(recoveryKeys).toHaveLength(NUMBER_OF_2FA_RECOVERY_KEYS);
    });

    it('should disable 2fa', async () => {
      const request = {
        userId: faker.number.int({ max: MAX_INT32 }),
      };
      jest.spyOn(authServcie, 'disable2fa');

      await authController.disable2fa(request);

      expect(authServcie.disable2fa).toHaveBeenCalled();
    });

    it('should verify 2fa token', async () => {
      const request = {
        userId: faker.number.int({ max: MAX_INT32 }),
        token: authenticator.generate(authenticator.generateSecret()),
      };

      const { accessToken } = await authController.verify2FA(request);

      expect(accessToken).toBeDefined();
      expect(typeof accessToken).toBe('string');
    });
  });
});
