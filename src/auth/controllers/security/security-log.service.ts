import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';
import { LogAction, LogStatus, SecurityLog } from '../../types';
import { Request as ExpressRequest } from 'express';

// Serviço responsável por gerenciar logs de segurança da aplicação
@Injectable()
export class SecurityLogService {
  constructor(private prisma: PrismaService) {}

  // Busca logs de segurança com paginação e filtros
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

  // Registra tentativa de login mal sucedida
  async logFailedLogin(userId: number | null, request: ExpressRequest) {
    await this.createLog({
      userId,
      action: LogAction.LOGIN,
      status: LogStatus.FAILURE,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || 'Unknown',
      details: JSON.stringify({
        timestamp: new Date(),
        headers: request.headers,
        geoLocation: request.headers['cf-ipcountry'],
      }),
    });
  }

  // Registra login bem sucedido
  async logSuccessfulLogin(userId: number, request: ExpressRequest) {
    await this.createLog({
      userId,
      action: LogAction.LOGIN,
      status: LogStatus.SUCCESS,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || 'Unknown',
    });
  }

  // Registra logout do usuário
  async logLogout(request: ExpressRequest) {
    await this.createLog({
      action: LogAction.LOGOUT,
      status: LogStatus.SUCCESS,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || 'Unknown',
    });
  }

  // Registra novo cadastro de usuário
  async logUserRegistration(userId: number, request: ExpressRequest) {
    await this.createLog({
      userId,
      action: LogAction.REGISTER,
      status: LogStatus.SUCCESS,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || 'Unknown',
    });
  }

  // Cria um novo registro de log no banco de dados
  public async createLog(data: SecurityLog) {
    return this.prisma.securityLog.create({
      data: {
        ...data,
      },
    });
  }

  // Constrói a cláusula where para filtrar logs
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

  // Formata os detalhes do log para exibição
  private formatLogDetails(log: any) {
    const userEmail = log.user?.email || 'Unknown user';
    return {
      ...log,
      details: this.generateLogDetails(log.action, log.status, userEmail),
    };
  }

  // Gera mensagem descritiva para cada tipo de log
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
