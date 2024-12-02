import { ConsoleLogger, Injectable, Scope } from '@nestjs/common';
import { SecurityLogService } from '../../auth/controllers/security/security-log.service';
import { LogAction, LogStatus, SecurityLog } from '../../auth/types';

@Injectable({ scope: Scope.TRANSIENT })
export class AppLogger extends ConsoleLogger {
  constructor(
    private securityLogService?: SecurityLogService,
    protected override context?: string,
  ) {
    super(context);
  }

  static forContext(context: string) {
    return new AppLogger(null, context);
  }

  log(message: string, context?: string) {
    super.log(message, context);
    this.saveLog('INFO', message, context);
  }

  error(message: string, trace?: string, context?: string) {
    super.error(message, trace, context);
    this.saveLog('ERROR', `${message} ${trace || ''}`, context);
  }

  warn(message: string, context?: string) {
    super.warn(message, context);
    this.saveLog('WARN', message, context);
  }

  debug(message: string, context?: string) {
    super.debug(message, context);
    this.saveLog('DEBUG', message, context);
  }

  private async saveLog(level: string, message: string, context?: string) {
    if (this.securityLogService) {
      try {
        const logEntry: SecurityLog = {
          action: LogAction.SYSTEM,
          status: level as LogStatus,
          details: JSON.stringify({
            message,
            context,
            timestamp: new Date().toISOString(),
          }),
          ipAddress: 'system',
          userAgent: context || 'system',
        };
        await this.securityLogService.createLog(logEntry);
      } catch (error) {
        super.error('Error saving log to database', error);
      }
    }
  }
}
