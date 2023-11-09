import { ApiProperty } from '@nestjs/swagger';

export class Create2faQrCodeResponse {
  @ApiProperty()
  public qrCodeUrl: string;
  constructor(qrCodeUrl: string) {
    this.qrCodeUrl = qrCodeUrl;
  }

  public static from(qrCodeUrl: string): Create2faQrCodeResponse {
    return new Create2faQrCodeResponse(qrCodeUrl);
  }
}
