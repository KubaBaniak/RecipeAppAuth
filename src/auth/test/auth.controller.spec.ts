import { AuthController } from '../auth.controller';
import { AuthService } from '../auth.service';
import { MockAuthService } from '../__mocks__/auth.service.mock';
import { Test, TestingModule } from '@nestjs/testing';
import { faker } from '@faker-js/faker';
import { MAX_INT32 } from '../constants';
import {
  PendingUserCredentialsRepository,
  UserCredentialsRepository,
} from '../repositories';
import { PrismaService } from '../../prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';

describe('AuthController', () => {
  let authController: AuthController;
  let authService: AuthService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        UserCredentialsRepository,
        PendingUserCredentialsRepository,
        JwtService,
        PrismaService,
        {
          provide: AuthService,
          useClass: MockAuthService,
        },
      ],
    }).compile();

    authController = module.get<AuthController>(AuthController);
    authService = module.get<AuthService>(AuthService);
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

  describe('Activate account', () => {
    it('should acctivate account', async () => {
      const token = faker.string.alphanumeric({ length: 64 });
      jest.spyOn(authService, 'activateAccount');

      await authController.activateAccount(token);

      expect(authService.activateAccount).toHaveBeenCalled();
    });
  });
});
