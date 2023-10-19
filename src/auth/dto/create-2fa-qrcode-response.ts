import { ApiProperty } from '@nestjs/swagger';

export class Create2faQrCodeResponse {
  @ApiProperty()
  public qrCodeUrl: string;
  @ApiProperty()
  public urlToEnable2FA = `${process.env.BASE_URL}/api/auth/enable-2fa`;

  constructor(qrCodeUrl: string) {
    this.qrCodeUrl = qrCodeUrl;
  }

  public static from(qrCodeUrl: string): Create2faQrCodeResponse {
    return new Create2faQrCodeResponse(qrCodeUrl);
  }
}
