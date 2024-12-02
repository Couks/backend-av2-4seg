import { IsEmail, IsString, MinLength, Matches } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class RegisterDto {
  @ApiProperty({ example: 'Matheus Castro' })
  @IsString()
  name: string;

  @ApiProperty({ example: 'matheuscastroks@gmail.com' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: '@Teste123123' })
  @IsString()
  @MinLength(8)
  @Matches(/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).*$/)
  password: string;
}
