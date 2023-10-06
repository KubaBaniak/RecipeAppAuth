import { SignUpRequest } from '../dto';

export class MockAuthService {
  signUp(signUpRequest: SignUpRequest): number {
    return signUpRequest.userId;
  }
}
