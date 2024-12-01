import { Controller, Post, Get, Headers } from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { TokenService } from './token.service';

@ApiTags('Token Management')
@Controller('api/token')
export class TokenController {
  constructor(private readonly tokenService: TokenService) {}

  @Get('refresh')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Refresh access token' })
  @ApiResponse({
    status: 200,
    description: 'Token refreshed successfully',
    schema: {
      example: { accessToken: 'eyJhbGciOiJIUzI1NiIs...' },
    },
  })
  async refreshToken(@Headers('authorization') auth: string) {
    const token = auth?.split(' ')[1];
    return this.tokenService.refreshToken(token);
  }

  @Post('validate')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Validate JWT token' })
  @ApiResponse({
    status: 200,
    description: 'Token validation result',
    schema: {
      example: {
        valid: true,
        payload: { sub: 1, iat: 1616161616, exp: 1616162616 },
      },
    },
  })
  async validateToken(@Headers('authorization') auth: string) {
    const token = auth?.split(' ')[1];
    return this.tokenService.validateToken(token);
  }
}
