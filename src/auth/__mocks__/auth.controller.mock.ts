import { faker } from '@faker-js/faker';
import { SignUpRequest, SignUpResponse } from '../dto';

export class MockAuthController {
  signUp(signUpRequest: SignUpRequest): Promise<SignUpResponse> {
    const signedUpUser = {
      id: faker.number.int(),
      email: signUpRequest.email,
      password: signUpRequest.password,
    };

    return Promise.resolve(SignUpResponse.from(signedUpUser));
  }
}
