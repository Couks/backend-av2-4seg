import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
  NotFoundException,
  InternalServerErrorException,
} from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';
import { EncryptionService } from '../../../common/encryption/encryption.service';
import { SecurityLogService } from '../security/security-log.service';
import { RegisterDto } from './dto/register.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import * as crypto from 'crypto';
import { Verify2FADto } from './dto/verify-2fa.dto';
import * as speakeasy from 'speakeasy';
import { JwtService } from '@nestjs/jwt';
import { TokenService } from '../token/token.service';
import { Request as ExpressRequest } from 'express';
import * as nodemailer from 'nodemailer';
import { VerifyEmailDto } from './dto/verify-email.dto';
import * as QRCode from 'qrcode';
import { AppLogger } from 'src/common/logger/app.logger';

@Injectable()
export class UserService {
  private readonly transporter: nodemailer.Transporter;

  constructor(
    private prisma: PrismaService,
    private encryption: EncryptionService,
    private securityLogService: SecurityLogService,
    private jwtService: JwtService,
    private tokenService: TokenService,
    private readonly logger: AppLogger,
  ) {
    this.transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      service: 'gmail',
      auth: {
        user: process.env.GOOGLE_EMAIL,
        pass: process.env.GOOGLE_PASSWORD,
      },
    });
  }

  async register(dto: RegisterDto, request: ExpressRequest) {
    this.logger.log(`Attempting to register user with email: ${dto.email}`);

    const existingUser = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (existingUser) {
      this.logger.warn(
        `Registration failed - Email already exists: ${dto.email}`,
      );
      throw new BadRequestException('Email already registered');
    }

    const hashedPassword = await this.encryption.hashPassword(dto.password);
    const verificationCode = Math.floor(
      100000 + Math.random() * 900000,
    ).toString();

    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        name: dto.name,
        password: hashedPassword,
        verificationCode,
        isVerified: false,
      },
      select: {
        id: true,
        email: true,
        name: true,
      },
    });

    this.logger.log(`User registered successfully: ${user.email}`);
    await this.sendVerificationEmail(user.email, verificationCode);
    await this.securityLogService.logUserRegistration(user.id, request);

    return {
      ...user,
      message: 'Please check your email for verification code',
    };
  }

  private async sendVerificationEmail(email: string, code: string) {
    this.logger.log(`Sending verification email to: ${email}`);
    const mailOptions = {
      from: {
        name: 'Verificação de Conta',
        address: process.env.GOOGLE_EMAIL,
      },
      to: email,
      subject: 'Verifique sua conta',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Verificação de Conta</h2>
          <p>Seu código de verificação é:</p>
          <h1 style="color: #007bff; font-size: 32px; letter-spacing: 5px;">${code}</h1>
          <p>Este código expira em 15 minutos.</p>
        </div>
      `,
    };

    try {
      await this.transporter.sendMail(mailOptions);
      this.logger.log(`Verification email sent successfully to: ${email}`);
    } catch (error) {
      this.logger.error(
        `Failed to send verification email to: ${email}`,
        error.stack,
      );
      throw error;
    }
  }

  private async sendVerificationConfirmationEmail(email: string) {
    this.logger.log(`Sending verification confirmation email to: ${email}`);
    const mailOptions = {
      from: {
        name: 'Verificação de Conta',
        address: process.env.GOOGLE_EMAIL,
      },
      to: email,
      subject: 'Conta Verificada com Sucesso',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Conta Verificada!</h2>
          <p>Sua conta foi verificada com sucesso.</p>
          <p>Agora você tem acesso completo à nossa plataforma.</p>
          <p>Obrigado por confirmar seu e-mail!</p>
        </div>
      `,
    };

    try {
      await this.transporter.sendMail(mailOptions);
      this.logger.log(
        `Verification confirmation email sent successfully to: ${email}`,
      );
    } catch (error) {
      this.logger.error(
        `Failed to send verification confirmation email to: ${email}`,
        error.stack,
      );
      throw error;
    }
  }

  async verifyEmail(dto: VerifyEmailDto) {
    this.logger.log(`Attempting to verify email for: ${dto.email}`);
    const user = await this.prisma.user.findFirst({
      where: {
        email: dto.email,
        verificationCode: dto.code,
        isVerified: false,
      },
    });

    if (!user) {
      this.logger.warn(`Invalid verification code for email: ${dto.email}`);
      throw new BadRequestException('Invalid verification code');
    }

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        isVerified: true,
        verificationCode: null,
      },
    });

    this.logger.log(`Email verified successfully for: ${dto.email}`);
    await this.sendVerificationConfirmationEmail(user.email);

    return { message: 'Email verified successfully' };
  }

  async enable2FA(userId: number) {
    this.logger.log(`Attempting to enable 2FA for user ID: ${userId}`);
    try {
      const user = await this.prisma.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        this.logger.warn(`User not found for 2FA enable attempt: ${userId}`);
        throw new NotFoundException('User not found');
      }

      if (user.twoFactorEnabled) {
        this.logger.warn(`2FA already enabled for user: ${userId}`);
        throw new BadRequestException('2FA is already enabled');
      }

      const secret = speakeasy.generateSecret({
        name: `2FA AV2 4SEG:${user.email}`,
      });

      await this.prisma.user.update({
        where: { id: userId },
        data: {
          twoFactorSecret: secret.base32,
          twoFactorEnabled: false,
        },
      });

      const otpauthUrl = speakeasy.otpauthURL({
        secret: secret.base32,
        label: user.email,
        issuer: '4SEG',
      });

      const qrCode = await QRCode.toDataURL(otpauthUrl);
      this.logger.log(`2FA setup successful for user: ${userId}`);

      return {
        secret: secret.base32,
        qrCode,
      };
    } catch (error) {
      this.logger.error(`Error enabling 2FA for user ${userId}:`, error.stack);
      throw new InternalServerErrorException('Failed to enable 2FA');
    }
  }

  async confirm2FA(userId: number, code: string) {
    this.logger.log(`Attempting to confirm 2FA for user ID: ${userId}`);

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        twoFactorSecret: true,
        twoFactorEnabled: true,
      },
    });

    if (!user?.twoFactorSecret) {
      this.logger.warn(`2FA not initialized for user: ${userId}`);
      throw new BadRequestException('2FA not initialized');
    }

    if (user.twoFactorEnabled) {
      this.logger.warn(`2FA already enabled for user: ${userId}`);
      throw new BadRequestException('2FA is already enabled');
    }

    const isValid = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: code,
      window: 2, // Permite 2 intervalos de 30s antes/depois
    });

    if (!isValid) {
      this.logger.warn(`Invalid 2FA code provided for user: ${userId}`);
      throw new UnauthorizedException('Invalid 2FA code');
    }

    await this.prisma.user.update({
      where: { id: userId },
      data: {
        twoFactorEnabled: true,
        twoFactorVerified: true,
      },
    });

    this.logger.log(`2FA confirmed successfully for user: ${userId}`);
    return { message: '2FA enabled successfully' };
  }

  async forgotPassword(dto: ForgotPasswordDto) {
    this.logger.log(`Password reset requested for email: ${dto.email}`);
    const recentRequests = await this.prisma.passwordReset.count({
      where: {
        email: dto.email,
        createdAt: {
          gt: new Date(Date.now() - 60 * 60 * 1000),
        },
      },
    });

    if (recentRequests >= 3) {
      this.logger.warn(`Too many reset requests for email: ${dto.email}`);
      throw new BadRequestException('Too many reset requests');
    }

    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) {
      this.logger.warn(`User not found for password reset: ${dto.email}`);
      throw new NotFoundException('User not found');
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    await this.createPasswordReset(dto.email, resetToken);

    const resetLink = `http://localhost:3000/reset-password?token=${resetToken}`;

    const mailOptions = {
      from: {
        name: 'Esqueceu sua senha?',
        address: process.env.GOOGLE_EMAIL,
      },
      to: dto.email,
      subject: 'Recuperação de Senha',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #333;">Recuperação de Senha</h2>
          <p>Você solicitou a recuperação de senha da sua conta.</p>
          <p>Clique no link abaixo para criar uma nova senha:</p>
          <a href="${resetLink}" 
             style="display: inline-block; 
                    padding: 10px 20px; 
                    background-color: #007bff; 
                    color: white; 
                    text-decoration: none; 
                    border-radius: 5px; 
                    margin: 20px 0;">
            Redefinir Senha
          </a>
          <p style="color: #666; font-size: 14px;">
            Este link é válido por 24 horas. Se você não solicitou esta recuperação, 
            ignore este email.
          </p>
          <p style="color: #666; font-size: 14px;">
            Por questões de segurança, não compartilhe este email com ninguém.
          </p>
        </div>
      `,
    };

    try {
      await this.transporter.sendMail(mailOptions);
      this.logger.log(
        `Password reset email sent successfully to: ${dto.email}`,
      );

      return {
        message: 'Password reset instructions sent to your email',
        success: true,
      };
    } catch (error) {
      this.logger.error(
        `Failed to send password reset email to: ${dto.email}`,
        error.stack,
      );
      throw new BadRequestException('Failed to send password reset email');
    }
  }

  async resetPassword(dto: ResetPasswordDto) {
    this.logger.log('Attempting to reset password with token');
    const resetRecord = await this.validateResetToken(dto.token);
    const hashedPassword = await this.encryption.hashPassword(dto.newPassword);

    await this.updatePassword(
      resetRecord.email,
      hashedPassword,
      resetRecord.id,
    );
    this.logger.log(
      `Password reset successful for email: ${resetRecord.email}`,
    );
    return { message: 'Password reset successfully' };
  }

  private async createPasswordReset(email: string, token: string) {
    this.logger.log(`Creating password reset record for email: ${email}`);
    await this.prisma.passwordReset.updateMany({
      where: {
        email,
        used: false,
      },
      data: {
        used: true,
      },
    });

    return this.prisma.passwordReset.create({
      data: {
        email,
        token,
        expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
      },
    });
  }

  private async validateResetToken(token: string) {
    this.logger.log('Validating reset token');
    const resetRecord = await this.prisma.passwordReset.findFirst({
      where: {
        token,
        used: false,
        expires: { gt: new Date() },
      },
    });

    if (!resetRecord) {
      this.logger.warn('Invalid or expired reset token');
      throw new BadRequestException('Invalid or expired reset token');
    }

    return resetRecord;
  }

  private async updatePassword(
    email: string,
    hashedPassword: string,
    resetId: number,
  ) {
    this.logger.log(`Updating password for email: ${email}`);
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

  async verify2FA(dto: Verify2FADto, request: ExpressRequest) {
    this.logger.log('Verifying 2FA code');
    const decoded = this.jwtService.verify(dto.tempToken);
    const user = await this.prisma.user.findUnique({
      where: { id: decoded.sub },
    });

    if (!user?.twoFactorSecret) {
      this.logger.warn(`2FA not enabled for user ID: ${decoded.sub}`);
      throw new UnauthorizedException('2FA not enabled');
    }

    const isCodeValid = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: dto.code,
      window: 1,
    });

    if (!isCodeValid) {
      this.logger.warn(`Invalid 2FA code for user ID: ${decoded.sub}`);
      await this.securityLogService.logFailedLogin(user.id, request);
      throw new UnauthorizedException('Invalid 2FA code');
    }

    const tokens = await this.tokenService.generateTokenPair(user.id);
    await this.securityLogService.logSuccessfulLogin(user.id, request);
    this.logger.log(`2FA verification successful for user ID: ${decoded.sub}`);

    return tokens;
  }
}
