import { IsString, Length } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class VerifyEmailDto {
  @ApiProperty({
    description: 'Código de verificação enviado por email',
    example: '123456',
  })
  @IsString()
  @Length(6, 6)
  code: string;

  @ApiProperty()
  @IsString()
  email: string;
}
