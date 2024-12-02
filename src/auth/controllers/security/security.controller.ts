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
import { CurrentUser } from '../../../common/decorators/current-user.decorator';
import { SanitizeInterceptor } from '../../../common/interceptors/sanitize.interceptor';
import { SecurityLogService } from './security-log.service';
import { JwtAuthGuard } from '../../guards/jwt-auth.guard';
import { AppLogger } from 'src/common/logger/app.logger';

@ApiTags('Security')
@Controller('api/security')
@UseGuards(JwtAuthGuard)
@UseInterceptors(SanitizeInterceptor)
@ApiBearerAuth()
export class SecurityController {
  private readonly CONTEXT = 'SecurityController';
  private readonly logger = AppLogger.forContext(this.CONTEXT);

  constructor(private readonly securityLogService: SecurityLogService) {}

  @Get('logs')
  @ApiOperation({
    summary: 'Get security logs',
    description: 'Retrieve security logs with pagination and filters',
  })
  @ApiQuery({
    name: 'page',
    required: false,
    type: Number,
    description: 'Page number',
  })
  @ApiQuery({
    name: 'limit',
    required: false,
    type: Number,
    description: 'Items per page',
  })
  @ApiQuery({
    name: 'action',
    required: false,
    enum: ['LOGIN', 'LOGOUT', 'REGISTER'],
  })
  @ApiQuery({ name: 'status', required: false, enum: ['SUCCESS', 'FAILURE'] })
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
            createdAt: '2024-01-01T00:00:00Z',
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
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getLogs(@Query() query: any, @CurrentUser() user: any) {
    this.logger.log(
      `Security logs request - User: ${user.userId}, Page: ${query.page || 1}`,
      this.CONTEXT,
    );
    try {
      this.logger.debug(`Query params: ${JSON.stringify(query)}`, this.CONTEXT);
      const result = await this.securityLogService.getSecurityLogs(
        query.page || 1,
        query.limit || 10,
        {
          userId: user.userId,
          ...query,
        },
      );
      this.logger.log(
        `Retrieved ${result.logs.length} logs successfully`,
        this.CONTEXT,
      );
      return result;
    } catch (error) {
      this.logger.error(
        `Failed to fetch security logs - User: ${user.userId}`,
        error.stack,
        this.CONTEXT,
      );
      throw error;
    }
  }
}
