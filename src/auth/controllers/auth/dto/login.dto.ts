import { IsEmail, IsString, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class LoginDto {
  @ApiProperty({ example: 'matheuscastroks@gmail.com' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: '@Teste123' })
  @IsString()
  @MinLength(8)
  password: string;
}
