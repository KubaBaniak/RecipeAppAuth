import { ApiProperty } from '@nestjs/swagger';
import { IsInt, IsNotEmpty, IsPositive } from 'class-validator';

export class Create2faQrCodeRequest {
  @IsInt()
  @IsPositive()
  @IsNotEmpty()
  @ApiProperty()
  readonly userId: number;
}
