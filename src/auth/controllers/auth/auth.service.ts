import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';
import { EncryptionService } from '../../../common/encryption/encryption.service';
import { TokenService } from '../token/token.service';
import { SecurityLogService } from '../security/security-log.service';
import { Request as ExpressRequest } from 'express';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private encryption: EncryptionService,
    private tokenService: TokenService,
    private securityLogService: SecurityLogService,
    private jwtService: JwtService,
  ) {}

  async login(dto: LoginDto, request: ExpressRequest) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
      select: {
        id: true,
        email: true,
        password: true,
        isVerified: true,
        twoFactorEnabled: true,
        twoFactorVerified: true,
      },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (!user.isVerified) {
      throw new UnauthorizedException('Email not verified');
    }

    const isPasswordValid = await this.encryption.comparePasswords(
      dto.password,
      user.password,
    );

    if (!isPasswordValid) {
      await this.securityLogService.logFailedLogin(user.id, request);
      throw new UnauthorizedException('Invalid credentials');
    }

    try {
      if (user.twoFactorEnabled && user.twoFactorVerified) {
        const tempToken = this.jwtService.sign(
          { sub: user.id, temp: true },
          { expiresIn: '5m' },
        );
        return { tempToken };
      }

      const tokens = await this.tokenService.generateTokenPair(user.id);
      await this.securityLogService.logSuccessfulLogin(user.id, request);
      return tokens;
    } catch (error) {
      console.error('Login error:', error);
      throw new UnauthorizedException('Authentication failed');
    }
  }

  async logout(token: string, request: ExpressRequest) {
    try {
      const decoded = this.jwtService.decode(token);

      if (decoded && typeof decoded === 'object' && decoded.sub) {
        await this.prisma.token.updateMany({
          where: {
            userId: decoded.sub,
            blacklisted: false,
          },
          data: { blacklisted: true },
        });
      }

      await this.tokenService.blacklistToken(token);

      await this.securityLogService.logLogout(request);

      return { message: 'Logged out successfully' };
    } catch (error) {
      console.error('Logout error:', error);
      return { message: 'Logged out successfully' };
    }
  }
}
