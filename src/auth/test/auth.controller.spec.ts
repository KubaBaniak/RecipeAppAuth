import { AuthController } from '../auth.controller';
import { AuthService } from '../auth.service';
import { MockAuthService } from '../__mocks__/auth.service.mock';
import { Test, TestingModule } from '@nestjs/testing';
import { faker } from '@faker-js/faker';
import { AUTH, MAX_INT32, NUMBER_OF_2FA_RECOVERY_KEYS } from '../constants';
import { JwtService } from '@nestjs/jwt';
import { authenticator } from 'otplib';

describe('AuthController', () => {
  let authController: AuthController;
  let authService: AuthService;
  let jwtService: JwtService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        JwtService,
        {
          provide: AuthService,
          useClass: MockAuthService,
        },
      ],
    }).compile();
    jest.clearAllMocks();

    authController = module.get<AuthController>(AuthController);
    authService = module.get<AuthService>(AuthService);
    jwtService = module.get<JwtService>(JwtService);
  });

  describe('SignUp', () => {
    it('should sign up user (not activated)', async () => {
      //given
      const request = {
        userId: faker.number.int({ max: MAX_INT32 }),
        password: faker.internet.password(),
      };

      //when
      const signedUpUser = await authController.signUp(request);

      //then
      expect(typeof signedUpUser.accountActivationToken).toEqual('string');
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

  describe('Personal access token', () => {
    it('should create personal access token', async () => {
      const request = {
        userId: faker.number.int({ max: MAX_INT32 }),
      };

      const createPatResponse = await authController.createPat(request);

      expect(createPatResponse).toBeDefined();
      expect(typeof createPatResponse.personalAccessToken).toBe('string');
      expect(
        jwtService.verify(createPatResponse.personalAccessToken, {
          secret: AUTH.PAT,
        }),
      ).toEqual({
        id: request.userId,
        iat: expect.any(Number),
      });
    });
  });

  describe('Change password', () => {
    it('should change password', async () => {
      const request = {
        userId: faker.number.int({ max: MAX_INT32 }),
        newPassword: faker.internet.password(),
      };
      jest.spyOn(authService, 'changePassword');

      await authController.changePassword(request);

      expect(authService.changePassword).toHaveBeenCalled();
    });
  });

  describe('Activate account', () => {
    it('should acctivate account', async () => {
      const token = faker.string.alphanumeric({ length: 64 });
      jest.spyOn(authService, 'activateAccount');

      await authController.activateAccount({ token });

      expect(authService.activateAccount).toHaveBeenCalled();
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
      jest.spyOn(authService, 'disable2fa');

      await authController.disable2fa(request);

      expect(authService.disable2fa).toHaveBeenCalled();
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

    it('should regenerate recovery keys', async () => {
      const request = {
        userId: faker.number.int({ max: MAX_INT32 }),
      };

      const { recoveryKeys } = await authController.regenerateRecoveryKeys(
        request,
      );

      expect(recoveryKeys).toBeDefined();
      expect(recoveryKeys).toBeInstanceOf(Array<string>);
      expect(recoveryKeys).toHaveLength(NUMBER_OF_2FA_RECOVERY_KEYS);
    });
  });
});
