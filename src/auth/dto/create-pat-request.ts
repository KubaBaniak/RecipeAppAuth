import { ApiProperty } from '@nestjs/swagger';
import { IsInt, IsNotEmpty, IsPositive } from 'class-validator';

export class CreatePatRequest {
  @IsInt()
  @IsPositive()
  @IsNotEmpty()
  @ApiProperty()
  readonly userId: number;
}
