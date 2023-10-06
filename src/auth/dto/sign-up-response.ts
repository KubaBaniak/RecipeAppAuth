import { ApiProperty } from '@nestjs/swagger';

ApiProperty;
export class SignUpResponse {
  @ApiProperty()
  public userId: number;

  constructor(userId: number) {
    this.userId = userId;
  }

  public static from(userId: number): SignUpResponse {
    return new SignUpResponse(userId);
  }
}
