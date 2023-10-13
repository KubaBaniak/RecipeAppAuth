import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from '../auth.service';
import { faker } from '@faker-js/faker';
import {
  PersonalAccessTokenRepository,
  UserCredentialsRepository,
} from '../repositories';
import { PrismaService } from '../../prisma/prisma.service';
import { MAX_INT32 } from '../constants';
import { MockPatRepository } from '../__mocks__';
import { JwtService } from '@nestjs/jwt';

describe('AuthService', () => {
  let authService: AuthService;
  let prismaService: PrismaService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        JwtService,
        PrismaService,
        UserCredentialsRepository,
        {
          provide: PersonalAccessTokenRepository,
          useClass: MockPatRepository,
        },
      ],
    }).compile();

    authService = module.get<AuthService>(AuthService);
    prismaService = module.get<PrismaService>(PrismaService);
  });

  afterAll(async () => {
    jest.clearAllMocks();
    await prismaService.userCredentials.deleteMany();
  });

  describe('SignUp', () => {
    it('should sign up user', async () => {
      //given
      const request = {
        userId: faker.number.int({ max: MAX_INT32 }),
        password: faker.internet.password(),
      };

      //when
      const userCredentials = await authService.signUp(request);

      //then
      expect(typeof userCredentials).toEqual('number');
      expect(userCredentials).toEqual(request.userId);
    });
  });

  describe('Personal access token', () => {
    it('should create personal access token', async () => {
      const userId = faker.number.int({ max: MAX_INT32 });

      const personalAccessToken = await authService.createPersonalAccessToken(
        userId,
      );

      expect(personalAccessToken).toBeDefined();
      expect(typeof personalAccessToken).toBe('string');
    });
  });
});
