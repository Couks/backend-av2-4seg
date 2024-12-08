import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  UseGuards,
  Headers,
  Req,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiBody,
  ApiHeader,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../../guards/jwt-auth.guard';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { Request } from 'express';
import { AppLogger } from 'src/common/logger/app.logger';
import { SecurityLogService } from '../security/security-log.service';
import { JwtService } from '@nestjs/jwt';

@ApiTags('Authentication')
@Controller('api')
export class AuthController {
  private readonly CONTEXT = 'AuthController';
  private readonly logger = AppLogger.forContext(this.CONTEXT);

  constructor(
    private readonly authService: AuthService,
    private readonly securityLogService: SecurityLogService,
    private readonly jwtService: JwtService,
  ) {}

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Authenticate user',
    description:
      'Authenticate user with email and password. Returns JWT tokens.',
  })
  @ApiBody({ type: LoginDto })
  @ApiResponse({
    status: 200,
    description: 'User authenticated successfully',
    schema: {
      example: {
        accessToken: 'eyJhbGciOiJIUzI1NiIs...',
        refreshToken: 'eyJhbGciOiJIUzI1NiIs...',
      },
    },
  })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  @ApiResponse({ status: 400, description: 'Invalid input data' })
  async login(@Body() dto: LoginDto, @Req() request: Request) {
    this.logger.log(`Login attempt for user: ${dto.email}`, this.CONTEXT);
    try {
      this.logger.debug(
        `Client info - IP: ${request.ip}, User-Agent: ${request.headers['user-agent']}`,
        this.CONTEXT,
      );
      const result = await this.authService.login(dto, request);
      const is2FARequired = 'tempToken' in result;
      this.logger.log(
        `Login successful for user: ${dto.email} - 2FA Required: ${is2FARequired}`,
        this.CONTEXT,
      );
      return result;
    } catch (error) {
      this.logger.error(
        `Login failed for user: ${dto.email}`,
        error.stack,
        this.CONTEXT,
      );
      throw error;
    }
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Logout user',
    description: 'Invalidate current user session and blacklist token',
  })
  @ApiHeader({
    name: 'Authorization',
    description: 'Bearer JWT token',
    required: true,
  })
  @ApiResponse({ status: 200, description: 'Logged out successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async logout(
    @Headers('authorization') auth: string,
    @Req() request: Request,
  ) {
    const token = auth?.split(' ')[1];
    this.logger.log(`Logout attempt - IP: ${request.ip}`, 'AuthController');
    try {
      const decoded = this.jwtService.decode(token);
      this.logger.debug(`Logout for user ID: ${decoded?.sub}`);
      const result = await this.authService.logout(auth, request);
      this.logger.log('Logout successful');
      return result;
    } catch (error) {
      this.logger.error('Logout failed', error.stack);
      throw error;
    }
  }
}
