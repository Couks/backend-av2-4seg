import { Controller, Post, Body } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { AuthService } from '../auth.service';
import { RegisterDto } from '../dto/register.dto';
import { Verify2FADto } from '../dto/verify-2fa.dto';
import { ForgotPasswordDto } from '../dto/forgot-password.dto';
import { ResetPasswordDto } from '../dto/reset-password.dto';

@ApiTags('Users')
@Controller('api/users')
export class UserController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @ApiOperation({ summary: 'Register a new user' })
  @ApiResponse({
    status: 201,
    description: 'User successfully registered',
    schema: {
      example: { message: 'User registered successfully' },
    },
  })
  async register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Post('2fa/verify')
  @ApiOperation({ summary: 'Verify 2FA code' })
  @ApiResponse({
    status: 200,
    description: '2FA verification successful',
    schema: {
      example: {
        accessToken: 'eyJhbGciOiJIUzI1NiIs...',
        refreshToken: 'eyJhbGciOiJIUzI1NiIs...',
      },
    },
  })
  async verify2FA(@Body() dto: Verify2FADto) {
    return this.authService.verify2FA(dto);
  }

  @Post('password/forgot')
  @ApiOperation({ summary: 'Request password reset' })
  @ApiResponse({
    status: 200,
    description: 'Password reset requested',
    schema: {
      example: { message: 'If the email exists, a reset link has been sent' },
    },
  })
  async forgotPassword(@Body() dto: ForgotPasswordDto) {
    return this.authService.forgotPassword(dto);
  }

  @Post('password/reset')
  @ApiOperation({ summary: 'Reset password' })
  @ApiResponse({
    status: 200,
    description: 'Password reset successful',
    schema: {
      example: { message: 'Password reset successfully' },
    },
  })
  async resetPassword(@Body() dto: ResetPasswordDto) {
    return this.authService.resetPassword(dto);
  }
}
