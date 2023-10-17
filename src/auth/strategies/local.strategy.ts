import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthService } from '../auth.service';
import { Strategies } from '../constants';
import { UserCredentialsRequest } from '../dto';

@Injectable()
export class LocalStrategy extends PassportStrategy(
  Strategy,
  Strategies.Local,
) {
  constructor(private authService: AuthService) {
    super({ usernameField: 'userId' });
  }

  async validate(userId: number, password: string): Promise<number> {
    const data: UserCredentialsRequest = { userId, password };
    const validatedUserId = await this.authService.validateUser(data);

    if (!validatedUserId) {
      throw new UnauthorizedException();
    }

    return validatedUserId;
  }
}
