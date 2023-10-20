import { ApiProperty } from '@nestjs/swagger';

export class RecoveryKeysRespnse {
  @ApiProperty({
    type: Array,
    items: {
      type: 'string',
    },
  })
  public recoveryKeys: string[];

  constructor(recoveryKeys: string[]) {
    this.recoveryKeys = recoveryKeys;
  }

  public static from(recoveryKeys: string[]): RecoveryKeysRespnse {
    return new RecoveryKeysRespnse(recoveryKeys);
  }
}
