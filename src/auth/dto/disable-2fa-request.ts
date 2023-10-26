import { ApiProperty } from '@nestjs/swagger';
import { IsInt, IsNotEmpty, IsPositive } from 'class-validator';

export class Disable2faRequest {
  @IsInt()
  @IsPositive()
  @IsNotEmpty()
  @ApiProperty()
  readonly userId: number;
}
