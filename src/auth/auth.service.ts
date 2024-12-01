import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { EncryptionService } from './encryption/encryption.service';
import { JwtService } from '@nestjs/jwt';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { Verify2FADto } from './dto/verify-2fa.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import * as speakeasy from 'speakeasy';
import * as crypto from 'crypto';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private encryption: EncryptionService,
    private jwtService: JwtService,
  ) {}

  async register(dto: RegisterDto) {
    const existingUser = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (existingUser) {
      throw new BadRequestException('Email already registered');
    }

    const hashedPassword = await this.encryption.hashPassword(dto.password);

    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        name: dto.name,
        password: hashedPassword,
      },
    });

    await this.prisma.securityLog.create({
      data: {
        userId: user.id,
        action: 'REGISTER',
        status: 'SUCCESS',
        ipAddress: '127.0.0.1',
        userAgent: 'Unknown',
      },
    });

    return { message: 'User registered successfully' };
  }

  async login(dto: LoginDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await this.encryption.comparePasswords(
      dto.password,
      user.password,
    );

    if (!isPasswordValid) {
      await this.logFailedLogin(user.id);
      throw new UnauthorizedException('Invalid credentials');
    }

    if (user.twoFactorEnabled) {
      // Retornar um token temporário para verificação 2FA
      return {
        requiresTwoFactor: true,
        tempToken: this.generateTempToken(user.id),
      };
    }

    const tokens = await this.generateTokens(user.id);
    await this.logSuccessfulLogin(user.id);

    return tokens;
  }

  private async generateTokens(userId: number) {
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync({ sub: userId }, { expiresIn: '15m' }),
      this.jwtService.signAsync({ sub: userId }, { expiresIn: '7d' }),
    ]);

    await this.prisma.token.create({
      data: {
        token: refreshToken,
        type: 'REFRESH',
        userId,
        expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      },
    });

    return {
      accessToken,
      refreshToken,
    };
  }

  private async logFailedLogin(userId: number) {
    await this.prisma.securityLog.create({
      data: {
        userId,
        action: 'LOGIN',
        status: 'FAILURE',
        ipAddress: '127.0.0.1',
        userAgent: 'Unknown',
      },
    });
  }

  private async logSuccessfulLogin(userId: number) {
    await this.prisma.securityLog.create({
      data: {
        userId,
        action: 'LOGIN',
        status: 'SUCCESS',
        ipAddress: '127.0.0.1',
        userAgent: 'Unknown',
      },
    });
  }

  private generateTempToken(userId: number): string {
    return this.jwtService.sign(
      {
        sub: userId,
        temp: true,
      },
      {
        expiresIn: '5m',
      },
    );
  }

  async logout(token: string) {
    await this.prisma.token.update({
      where: { token },
      data: { blacklisted: true },
    });

    await this.prisma.securityLog.create({
      data: {
        action: 'LOGOUT',
        status: 'SUCCESS',
        ipAddress: '127.0.0.1',
        userAgent: 'Unknown',
      },
    });

    return { message: 'Logged out successfully' };
  }

  async refreshToken(refreshToken: string) {
    const tokenRecord = await this.prisma.token.findUnique({
      where: { token: refreshToken },
      include: { user: true },
    });

    if (
      !tokenRecord ||
      tokenRecord.blacklisted ||
      tokenRecord.expires < new Date()
    ) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const newAccessToken = await this.jwtService.signAsync(
      { sub: tokenRecord.userId },
      { expiresIn: '15m' },
    );

    await this.prisma.securityLog.create({
      data: {
        userId: tokenRecord.userId,
        action: 'TOKEN_REFRESH',
        status: 'SUCCESS',
        ipAddress: '127.0.0.1',
        userAgent: 'Unknown',
      },
    });

    return { accessToken: newAccessToken };
  }

  async verify2FA(dto: Verify2FADto) {
    const decoded = this.jwtService.verify(dto.tempToken);
    const user = await this.prisma.user.findUnique({
      where: { id: decoded.sub },
    });

    if (!user?.twoFactorSecret) {
      throw new UnauthorizedException('2FA not enabled');
    }

    const isCodeValid = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: dto.code,
    });

    if (!isCodeValid) {
      await this.prisma.securityLog.create({
        data: {
          userId: user.id,
          action: 'TWO_FACTOR_VERIFY',
          status: 'FAILURE',
          ipAddress: '127.0.0.1',
          userAgent: 'Unknown',
        },
      });
      throw new UnauthorizedException('Invalid 2FA code');
    }

    const tokens = await this.generateTokens(user.id);
    await this.logSuccessfulLogin(user.id);

    return tokens;
  }

  async forgotPassword(dto: ForgotPasswordDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (user) {
      const resetToken = crypto.randomBytes(32).toString('hex');

      await this.prisma.passwordReset.create({
        data: {
          email: dto.email,
          token: resetToken,
          expires: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
        },
      });

      // TODO: Implement email sending
      console.log(`Reset token for ${dto.email}: ${resetToken}`);
    }

    return { message: 'If the email exists, a reset link has been sent' };
  }

  async resetPassword(dto: ResetPasswordDto) {
    const resetRecord = await this.prisma.passwordReset.findFirst({
      where: {
        token: dto.token,
        used: false,
        expires: { gt: new Date() },
      },
    });

    if (!resetRecord) {
      throw new UnauthorizedException('Invalid or expired reset token');
    }

    const hashedPassword = await this.encryption.hashPassword(dto.newPassword);

    await Promise.all([
      this.prisma.user.update({
        where: { email: resetRecord.email },
        data: { password: hashedPassword },
      }),
      this.prisma.passwordReset.update({
        where: { id: resetRecord.id },
        data: { used: true },
      }),
    ]);

    return { message: 'Password reset successfully' };
  }

  async validateToken(token: string) {
    try {
      const decoded = await this.jwtService.verifyAsync(token);
      const tokenRecord = await this.prisma.token.findFirst({
        where: {
          token,
          blacklisted: false,
          expires: { gt: new Date() },
        },
      });

      if (!tokenRecord) {
        return { valid: false, error: 'Token blacklisted or expired' };
      }

      return { valid: true, payload: decoded };
    } catch (error) {
      return { valid: false, error: error.message };
    }
  }

  async getSecurityLogs(
    page: number,
    limit: number,
    action?: string,
    status?: string,
    userId?: number,
    startDate?: string,
    endDate?: string,
  ) {
    const skip = (page - 1) * limit;

    const where = {
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

    const [logs, total] = await Promise.all([
      this.prisma.securityLog.findMany({
        where,
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' },
        include: {
          user: {
            select: {
              email: true,
            },
          },
        },
      }),
      this.prisma.securityLog.count({ where }),
    ]);

    return {
      logs: logs.map((log) => ({
        ...log,
        details: this.generateLogDetails(log),
      })),
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    };
  }

  private generateLogDetails(log: any): string {
    const userEmail = log.user?.email || 'Unknown user';

    switch (log.action) {
      case 'LOGIN':
        return `${log.status === 'SUCCESS' ? 'Successful' : 'Failed'} login attempt for ${userEmail}`;
      case 'LOGOUT':
        return `User ${userEmail} logged out`;
      case 'PASSWORD_RESET':
        return `Password reset ${log.status.toLowerCase()} for ${userEmail}`;
      case 'TWO_FACTOR_VERIFY':
        return `2FA verification ${log.status.toLowerCase()} for ${userEmail}`;
      default:
        return `${log.action} ${log.status.toLowerCase()} for ${userEmail}`;
    }
  }
}
