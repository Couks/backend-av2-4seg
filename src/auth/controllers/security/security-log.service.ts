import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';

@Injectable()
export class SecurityLogService {
  constructor(private prisma: PrismaService) {}

  async getSecurityLogs(
    page: number,
    limit: number,
    filters: {
      action?: string;
      status?: string;
      userId?: number;
      startDate?: string;
      endDate?: string;
    },
  ) {
    const skip = (page - 1) * limit;
    const where = this.buildWhereClause(filters);

    const [logs, total] = await Promise.all([
      this.prisma.securityLog.findMany({
        where,
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' },
        include: { user: { select: { email: true } } },
      }),
      this.prisma.securityLog.count({ where }),
    ]);

    return {
      logs: logs.map(this.formatLogDetails),
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    };
  }

  async logFailedLogin(userId: number) {
    await this.createLog({
      userId,
      action: 'LOGIN',
      status: 'FAILURE',
    });
  }

  async logSuccessfulLogin(userId: number) {
    await this.createLog({
      userId,
      action: 'LOGIN',
      status: 'SUCCESS',
    });
  }

  async logLogout() {
    await this.createLog({
      action: 'LOGOUT',
      status: 'SUCCESS',
    });
  }

  async logUserRegistration(userId: number) {
    await this.createLog({
      userId,
      action: 'REGISTER',
      status: 'SUCCESS',
    });
  }

  private async createLog(data: {
    userId?: number;
    action: string;
    status: string;
  }) {
    return this.prisma.securityLog.create({
      data: {
        ...data,
        ipAddress: '127.0.0.1',
        userAgent: 'Unknown',
      },
    });
  }

  private buildWhereClause(filters: any) {
    const { action, status, userId, startDate, endDate } = filters;
    return {
      ...(action && { action }),
      ...(status && { status }),
      ...(userId && { userId }),
      ...(startDate &&
        endDate && {
          createdAt: {
            gte: new Date(startDate),
            lte: new Date(endDate),
          },
        }),
    };
  }

  private formatLogDetails(log: any) {
    const userEmail = log.user?.email || 'Unknown user';
    return {
      ...log,
      details: this.generateLogDetails(log.action, log.status, userEmail),
    };
  }

  private generateLogDetails(
    action: string,
    status: string,
    userEmail: string,
  ): string {
    switch (action) {
      case 'LOGIN':
        return `${status === 'SUCCESS' ? 'Successful' : 'Failed'} login attempt for ${userEmail}`;
      case 'LOGOUT':
        return `User ${userEmail} logged out`;
      case 'PASSWORD_RESET':
        return `Password reset ${status.toLowerCase()} for ${userEmail}`;
      case 'TWO_FACTOR_VERIFY':
        return `2FA verification ${status.toLowerCase()} for ${userEmail}`;
      default:
        return `${action} ${status.toLowerCase()} for ${userEmail}`;
    }
  }
}
