import { ApiProperty } from '@nestjs/swagger';

ApiProperty;
export class CreatePatResponse {
  @ApiProperty()
  public personalAccessToken: string;

  constructor(personalAccessToken: string) {
    this.personalAccessToken = personalAccessToken;
  }

  public static from(personalAccessToken: string): CreatePatResponse {
    return new CreatePatResponse(personalAccessToken);
  }
}
