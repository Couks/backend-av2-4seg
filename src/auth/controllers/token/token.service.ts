import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../../prisma/prisma.service';
import { SecurityLogService } from '../security/security-log.service';
import { Request } from 'express';
import { AppLogger } from 'src/common/logger/app.logger';

@Injectable()
export class TokenService {
  private readonly CONTEXT = 'TokenService';

  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private securityLogService: SecurityLogService,
    private readonly logger: AppLogger,
  ) {}

  async generateTokenPair(userId: number) {
    try {
      // Limpa apenas tokens expirados ou já na blacklist
      await this.cleanupOldTokens(userId);

      const [accessToken, refreshToken] = await Promise.all([
        this.jwtService.signAsync(
          { sub: userId, type: 'access' },
          { expiresIn: '15m' },
        ),
        this.jwtService.signAsync(
          { sub: userId, type: 'refresh' },
          { expiresIn: '7d' },
        ),
      ]);

      // Salva o refresh token sem invalidar outros tokens válidos
      await this.saveRefreshToken(refreshToken, userId);

      return { accessToken, refreshToken };
    } catch (error) {
      console.error('[TokenService] Error generating token pair:', error);
      throw new UnauthorizedException('Error generating tokens');
    }
  }

  async refreshToken(token: string, request: Request) {
    try {
      // Verificar se token existe no banco primeiro
      const tokenRecord = await this.prisma.token.findFirst({
        where: {
          token: { contains: token },
          blacklisted: false,
          expires: { gt: new Date() },
        },
      });

      if (!tokenRecord) {
        this.logger.warn('Token not found or expired', this.CONTEXT);
        throw new UnauthorizedException('Invalid refresh token');
      }

      // Então verificar JWT
      const payload = this.jwtService.verify(token);
      if (payload.type !== 'refresh') {
        this.logger.warn('Invalid token type for refresh', this.CONTEXT);
        throw new UnauthorizedException('Invalid token type');
      }

      // Gerar novo access token
      const accessToken = this.jwtService.sign(
        { sub: payload.sub, type: 'access' },
        { expiresIn: '15m' },
      );

      this.logger.log(`Token refreshed for user: ${payload.sub}`, this.CONTEXT);
      return { accessToken };
    } catch (error) {
      this.logger.error('Token refresh failed:', error.stack, this.CONTEXT);
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  private async cleanupOldTokens(userId: number) {
    try {
      const result = await this.prisma.token.deleteMany({
        where: {
          userId,
          OR: [
            { expires: { lt: new Date() } }, // Apenas tokens expirados
            { blacklisted: true }, // Ou tokens na blacklist
          ],
        },
      });
    } catch (error) {
      console.error('[TokenService] Error cleaning up tokens:', error);
    }
  }

  private async saveRefreshToken(token: string, userId: number) {
    const uniqueToken = `${token}_${Date.now()}`;
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    try {
      // Não invalida outros tokens, apenas salva o novo
      const savedToken = await this.prisma.token.create({
        data: {
          token: uniqueToken,
          type: 'refresh',
          expires: expiresAt,
          userId,
        },
      });

      return savedToken;
    } catch (error) {
      console.error('[TokenService] Error saving refresh token:', error);
      throw error;
    }
  }

  async validateToken(
    token: string,
  ): Promise<{ valid: boolean; payload?: any }> {
    try {
      // Primeiro verifica se é um JWT válido
      const payload = await this.jwtService.verifyAsync(token);

      // Se for um access token, não precisa verificar no banco
      if (payload.type === 'access') {
        return { valid: true, payload };
      }

      // Se for refresh token, verifica no banco
      const tokenRecord = await this.prisma.token.findFirst({
        where: {
          token: { contains: token },
          blacklisted: false,
          expires: { gt: new Date() },
        },
      });

      if (!tokenRecord) {
        return { valid: false };
      }

      return { valid: true, payload };
    } catch (error) {
      console.error('[TokenService] Token validation error:', error);
      return { valid: false };
    }
  }

  async blacklistToken(token: string) {
    try {
      await this.prisma.token.updateMany({
        where: { token: { contains: token } },
        data: { blacklisted: true },
      });
    } catch (error) {
      console.error('[TokenService] Error blacklisting token:', error);
    }
  }

  private maskToken(token: string): string {
    // Implementação para mascarar o token
    return '**********';
  }
}
