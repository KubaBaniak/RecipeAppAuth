import { ApiProperty } from '@nestjs/swagger';

ApiProperty;
export class SignUpResponse {
  @ApiProperty()
  public accountActivationToken: string;

  constructor(accountActivationToken: string) {
    this.accountActivationToken = accountActivationToken;
  }

  public static from(accountActivationToken: string): SignUpResponse {
    return new SignUpResponse(accountActivationToken);
  }
}
