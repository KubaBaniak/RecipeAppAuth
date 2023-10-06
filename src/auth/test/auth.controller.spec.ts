import { AuthController } from '../auth.controller';
import { AuthService } from '../auth.service';
import { MockAuthService } from '../__mocks__/auth.service.mock';
import { Test, TestingModule } from '@nestjs/testing';
import { faker } from '@faker-js/faker';
import { MAX_INT32 } from '../constants';
import { UserCredentialsRepository } from '../repositories';
import { PrismaService } from '../../prisma/prisma.service';

describe('AuthController', () => {
  let authController: AuthController;
  let authService: AuthService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        UserCredentialsRepository,
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
});
