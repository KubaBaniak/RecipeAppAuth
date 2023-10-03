import { ForbiddenException, Injectable } from '@nestjs/common';
import { BCRYPT } from './constants';
import * as bcrypt from 'bcryptjs';
import { SignUpRequest } from './dto';

@Injectable()
export class AuthService {
  constructor() {}

  async signUp(signUpRequest: SignUpRequest): Promise<any> {
    const pendingUser = null;
    const user = null;

    if (pendingUser || user) {
      throw new ForbiddenException();
    }

    const hash = await bcrypt.hash(signUpRequest.password, BCRYPT.salt);

    const data = { email: signUpRequest.email, password: hash };

    return data;
  }
}
