import { AuthController } from '../auth.controller';
import { AuthService } from '../auth.service';
import { MockAuthService } from '../__mocks__/auth.service.mock';
import { Test, TestingModule } from '@nestjs/testing';
import { faker } from '@faker-js/faker';
import { MAX_INT32 } from '../constants';
import {
  TwoFactorAuthRepository,
  UserCredentialsRepository,
} from '../repositories';
import { PrismaService } from '../../prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';

describe('AuthController', () => {
  let authController: AuthController;

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
      const request = {
        userId: faker.number.int(),
        password: faker.internet.password({ length: 64 }),
      };

      const { accessToken } = await authController.signIn(request);

      expect(accessToken).toBeDefined();
      expect(typeof accessToken).toBe('string');
    });
  });

  describe('Two factor authentication', () => {
    it('should create qrcode for 2FA', async () => {
      const request = {
        userId: faker.number.int({ max: MAX_INT32 }),
      };

      const qrCodeObject = await authController.create2faQrCode(request);

      expect(qrCodeObject).toBeDefined();
      expect(typeof qrCodeObject.qrCodeUrl).toBe('string');
      expect(typeof qrCodeObject.urlToEnable2FA).toBe('string');
    });
  });
});
