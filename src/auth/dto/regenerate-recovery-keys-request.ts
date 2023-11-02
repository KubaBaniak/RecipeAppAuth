import { ApiProperty } from '@nestjs/swagger';
import { IsInt, IsNotEmpty, IsPositive } from 'class-validator';

export class RegenerateRecoveryKeysRequest {
  @IsInt()
  @IsPositive()
  @IsNotEmpty()
  @ApiProperty()
  readonly userId: number;
}
