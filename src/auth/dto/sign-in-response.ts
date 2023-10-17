import { ApiProperty } from '@nestjs/swagger';

export class SignInResponse {
  @ApiProperty()
  public accessToken: string;

  constructor(accessToken: string) {
    this.accessToken = accessToken;
  }

  public static from(accessToken: string): SignInResponse {
    return new SignInResponse(accessToken);
  }
}
