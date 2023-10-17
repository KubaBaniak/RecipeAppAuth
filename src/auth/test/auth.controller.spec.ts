import { AuthController } from '../auth.controller';
import { AuthService } from '../auth.service';
import { MockAuthService } from '../__mocks__/auth.service.mock';
import { Test, TestingModule } from '@nestjs/testing';
import { faker } from '@faker-js/faker';
import { MAX_INT32 } from '../constants';
import {
  PersonalAccessTokenRepository,
  UserCredentialsRepository,
} from '../repositories';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../prisma/prisma.service';

describe('AuthController', () => {
  let authController: AuthController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        PrismaService,
        UserCredentialsRepository,
        PersonalAccessTokenRepository,
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

  describe('Personal access token', () => {
    it('should create personal access token', async () => {
      const request = {
        userId: faker.number.int({ max: MAX_INT32 }),
      };

      const createPatResponse = await authController.createPat(request);

      expect(createPatResponse).toBeDefined();
      expect(typeof createPatResponse.personalAccessToken).toBe('string');
    });
  });
});
