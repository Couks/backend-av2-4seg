import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../../prisma/prisma.service';
import { SecurityLogService } from '../security/security-log.service';

@Injectable()
export class TokenService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private securityLogService: SecurityLogService,
  ) {}

  async generateTokenPair(userId: number) {
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync({ sub: userId }, { expiresIn: '15m' }),
      this.jwtService.signAsync({ sub: userId }, { expiresIn: '7d' }),
    ]);

    await this.saveRefreshToken(refreshToken, userId);

    return { accessToken, refreshToken };
  }

  generateTempToken(userId: number): string {
    return this.jwtService.sign(
      { sub: userId, temp: true },
      { expiresIn: '5m' },
    );
  }

  async validateToken(token: string) {
    try {
      const decoded = await this.jwtService.verifyAsync(token);
      const isValid = await this.checkTokenValidity(token);
      return isValid
        ? { valid: true, payload: decoded }
        : { valid: false, error: 'Token blacklisted or expired' };
    } catch (error) {
      return { valid: false, error: error.message };
    }
  }

  async blacklistToken(token: string) {
    await this.prisma.token.update({
      where: { token },
      data: { blacklisted: true },
    });
  }

  private async saveRefreshToken(token: string, userId: number) {
    await this.prisma.token.create({
      data: {
        token,
        type: 'REFRESH',
        userId,
        expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      },
    });
  }

  private async checkTokenValidity(token: string) {
    const tokenRecord = await this.prisma.token.findFirst({
      where: {
        token,
        blacklisted: false,
        expires: { gt: new Date() },
      },
    });
    return !!tokenRecord;
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

    await this.securityLogService.logSuccessfulLogin(tokenRecord.userId);

    return { accessToken: newAccessToken };
  }
}
