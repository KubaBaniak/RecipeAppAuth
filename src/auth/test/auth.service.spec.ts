import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from '../auth.service';
import { faker } from '@faker-js/faker';
import { MockContext, createMockContext } from '../../prisma/__mocks__/context';
import { UserCredentialsRepository } from '../user-credentials.repository';
import { PrismaService } from '../../prisma/prisma.service';
import { MAX_INT32 } from '../constants';

describe('AuthService', () => {
  let authService: AuthService;
  let prismaService: PrismaService;
  let mockCtx: MockContext;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [AuthService, UserCredentialsRepository, PrismaService],
    }).compile();

    authService = module.get<AuthService>(AuthService);
    prismaService = module.get<PrismaService>(PrismaService);

    mockCtx = createMockContext();
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
      mockCtx.prisma.userCredentials.create.mockResolvedValue({
        userId: request.userId,
        password: request.password,
      });

      //when
      const userCredentials = await authService.signUp(request);

      //then
      expect(typeof userCredentials).toEqual('number');
      expect(userCredentials).toEqual(request.userId);
    });
  });
});
