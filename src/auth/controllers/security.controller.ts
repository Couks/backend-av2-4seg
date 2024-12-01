import {
  Controller,
  Get,
  Query,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiQuery,
} from '@nestjs/swagger';
import { AuthService } from '../auth.service';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { CurrentUser } from '../decorators/current-user.decorator';
import { SanitizeInterceptor } from '../interceptors/sanitize.interceptor';

@ApiTags('Security')
@Controller('api/security')
@UseGuards(JwtAuthGuard)
@UseInterceptors(SanitizeInterceptor)
@ApiBearerAuth()
export class SecurityController {
  constructor(private readonly authService: AuthService) {}

  @Get('logs')
  @ApiOperation({ summary: 'Get security logs with filters' })
  @ApiQuery({ name: 'page', required: false, type: Number })
  @ApiQuery({ name: 'limit', required: false, type: Number })
  @ApiQuery({
    name: 'action',
    required: false,
    enum: ['LOGIN', 'LOGOUT', 'PASSWORD_RESET', 'TWO_FACTOR_VERIFY'],
  })
  @ApiQuery({ name: 'status', required: false, enum: ['SUCCESS', 'FAILURE'] })
  @ApiQuery({ name: 'startDate', required: false, type: String })
  @ApiQuery({ name: 'endDate', required: false, type: String })
  @ApiResponse({
    status: 200,
    description: 'Security logs retrieved successfully',
    schema: {
      example: {
        logs: [
          {
            id: 1,
            action: 'LOGIN',
            status: 'SUCCESS',
            ipAddress: '127.0.0.1',
            userAgent: 'Mozilla/5.0...',
            details: 'Login successful for user@example.com',
            createdAt: '2024-03-19T12:00:00Z',
          },
        ],
        pagination: {
          page: 1,
          limit: 10,
          total: 50,
          totalPages: 5,
        },
      },
    },
  })
  async getLogs(
    @CurrentUser() user: any,
    @Query('page') page = 1,
    @Query('limit') limit = 10,
    @Query('action') action?: string,
    @Query('status') status?: string,
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
  ) {
    return this.authService.getSecurityLogs(
      page,
      limit,
      action,
      status,
      user.userId,
      startDate,
      endDate,
    );
  }
}
