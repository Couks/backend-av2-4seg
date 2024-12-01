import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';
import { EncryptionService } from '../../encryption/encryption.service';
import { SecurityLogService } from '../security/security-log.service';
import { RegisterDto } from '../../dto/register.dto';
import { ForgotPasswordDto } from '../../dto/forgot-password.dto';
import { ResetPasswordDto } from '../../dto/reset-password.dto';
import * as crypto from 'crypto';
import { Verify2FADto } from '../../dto/verify-2fa.dto';
import * as speakeasy from 'speakeasy';
import { JwtService } from '@nestjs/jwt';
import { TokenService } from '../token/token.service';

@Injectable()
export class UserService {
  constructor(
    private prisma: PrismaService,
    private encryption: EncryptionService,
    private securityLogService: SecurityLogService,
    private jwtService: JwtService,
    private tokenService: TokenService,
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

    await this.securityLogService.logUserRegistration(user.id);
    return { message: 'User registered successfully' };
  }

  async forgotPassword(dto: ForgotPasswordDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (user) {
      const resetToken = crypto.randomBytes(32).toString('hex');
      await this.createPasswordReset(dto.email, resetToken);
      // TODO: Implement email sending
    }

    return { message: 'If the email exists, a reset link has been sent' };
  }

  async resetPassword(dto: ResetPasswordDto) {
    const resetRecord = await this.validateResetToken(dto.token);
    const hashedPassword = await this.encryption.hashPassword(dto.newPassword);

    await this.updatePassword(
      resetRecord.email,
      hashedPassword,
      resetRecord.id,
    );
    return { message: 'Password reset successfully' };
  }

  private async createPasswordReset(email: string, token: string) {
    return this.prisma.passwordReset.create({
      data: {
        email,
        token,
        expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
      },
    });
  }

  private async validateResetToken(token: string) {
    const resetRecord = await this.prisma.passwordReset.findFirst({
      where: {
        token,
        used: false,
        expires: { gt: new Date() },
      },
    });

    if (!resetRecord) {
      throw new BadRequestException('Invalid or expired reset token');
    }

    return resetRecord;
  }

  private async updatePassword(
    email: string,
    hashedPassword: string,
    resetId: number,
  ) {
    await Promise.all([
      this.prisma.user.update({
        where: { email },
        data: { password: hashedPassword },
      }),
      this.prisma.passwordReset.update({
        where: { id: resetId },
        data: { used: true },
      }),
    ]);
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
      await this.securityLogService.logFailedLogin(user.id);
      throw new UnauthorizedException('Invalid 2FA code');
    }

    const tokens = await this.tokenService.generateTokenPair(user.id);
    await this.securityLogService.logSuccessfulLogin(user.id);

    return tokens;
  }
}
