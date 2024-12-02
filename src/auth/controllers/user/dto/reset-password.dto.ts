import { IsString, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ResetPasswordDto {
  @ApiProperty({ example: 'reset-token-123' })
  @IsString()
  token: string;

  @ApiProperty({ example: 'new@Teste123' })
  @IsString()
  @MinLength(8)
  newPassword: string;
}
