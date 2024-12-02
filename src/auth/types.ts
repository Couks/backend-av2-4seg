export interface UserPayload {
  userId: number;
  email: string;
}

export enum LogAction {
  LOGIN = 'LOGIN',
  LOGOUT = 'LOGOUT',
  REGISTER = 'REGISTER',
  PASSWORD_RESET = 'PASSWORD_RESET',
  TWO_FACTOR_VERIFY = 'TWO_FACTOR_VERIFY',
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
  SYSTEM = 'SYSTEM',
}

export enum LogStatus {
  SUCCESS = 'SUCCESS',
  FAILURE = 'FAILURE',
  INFO = 'INFO',
  ERROR = 'ERROR',
  WARN = 'WARN',
  DEBUG = 'DEBUG',
}

export interface SecurityLog {
  userId?: number;
  action: LogAction;
  status: LogStatus;
  ipAddress: string;
  userAgent: string;
  details?: string;
}
