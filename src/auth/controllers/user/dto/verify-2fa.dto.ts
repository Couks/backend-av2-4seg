import { IsString, IsOptional } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class Verify2FADto {
  @ApiProperty({ example: '123456' })
  @IsString()
  code: string;

  @ApiProperty({ example: '' })
  @IsString()
  @IsOptional()
  tempToken?: string;
}
