import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from '../auth.service';
import { faker } from '@faker-js/faker';
import { UserCredentialsRepository } from '../repositories';
import { PrismaService } from '../../prisma/prisma.service';
import { MAX_INT32 } from '../constants';
import { MockUserCredentialsRepository } from '../__mocks__';

describe('AuthService', () => {
  let authService: AuthService;
  let userCredentialsRepository: UserCredentialsRepository;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        PrismaService,
        {
          provide: UserCredentialsRepository,
          useClass: MockUserCredentialsRepository,
        },
      ],
    }).compile();

    authService = module.get<AuthService>(AuthService);
    userCredentialsRepository = module.get<UserCredentialsRepository>(
      UserCredentialsRepository,
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

  describe('Change password', () => {
    it('should change password', async () => {
      const request = {
        userId: faker.number.int({ max: MAX_INT32 }),
        newPassword: faker.internet.password(),
      };

      const userId = await authService.changePassword(request);

      expect(typeof userId).toEqual('number');
      expect(userId).toEqual(request.userId);
    });
  });
});
