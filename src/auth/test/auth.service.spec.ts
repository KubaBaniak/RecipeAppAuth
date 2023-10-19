import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from '../auth.service';
import { faker } from '@faker-js/faker';
import {
  UserCredentialsRepository,
  PendingUserCredentialsRepository,
} from '../repositories';
import * as bcrypt from 'bcryptjs';
import { BCRYPT, MAX_INT32, SECRETS } from '../constants';
import { PrismaService } from '../../prisma/prisma.service';
import {
  MockUserCredentialsRepository,
  MockPendingUserCredentialsRepository,
} from '../__mocks__';
import { JwtService } from '@nestjs/jwt';

describe('AuthService', () => {
  let authService: AuthService;
  let userCredentialsRepository: UserCredentialsRepository;
  let pendingUserCredentialsRepository: PendingUserCredentialsRepository;
  let jwtServcie: JwtService;

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
          provide: PendingUserCredentialsRepository,
          useClass: MockPendingUserCredentialsRepository,
        },
      ],
    }).compile();

    authService = module.get<AuthService>(AuthService);
    jwtServcie = module.get<JwtService>(JwtService);
    userCredentialsRepository = module.get<UserCredentialsRepository>(
      UserCredentialsRepository,
    );
    pendingUserCredentialsRepository =
      module.get<PendingUserCredentialsRepository>(
        PendingUserCredentialsRepository,
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
      jest
        .spyOn(
          pendingUserCredentialsRepository,
          'getPendingUserCredentialsById',
        )
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

  describe('Activate account', () => {
    it('should activate account', async () => {
      const userId = faker.number.int({ max: MAX_INT32 });
      jest.spyOn(userCredentialsRepository, 'storeUserCredentials');
      jest.spyOn(
        pendingUserCredentialsRepository,
        'getPendingUserCredentialsById',
      );
      jest.spyOn(
        pendingUserCredentialsRepository,
        'removePendingUserCredentialsById',
      );

      const activatedUserCredentials = await authService.activateAccount(
        userId,
      );

      expect(typeof activatedUserCredentials).toBe('number');
      expect(userCredentialsRepository.storeUserCredentials).toHaveBeenCalled();
      expect(
        pendingUserCredentialsRepository.getPendingUserCredentialsById,
      ).toHaveBeenCalled();
      expect(
        pendingUserCredentialsRepository.removePendingUserCredentialsById,
      ).toHaveBeenCalled();
    });

    it('should verify account activation token', async () => {
      const userId = faker.number.int({ max: MAX_INT32 });
      const accountActivationToken = jwtServcie.sign(
        { id: userId },
        {
          secret: SECRETS.ACCOUNT_ACTIVATION,
        },
      );

      const tokenPayload = await authService.verifyAccountActivationToken(
        accountActivationToken,
      );

      expect(tokenPayload.id).toEqual(userId);
    });
  });
});
