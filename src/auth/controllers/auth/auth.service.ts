import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';
import { EncryptionService } from '../../../common/encryption/encryption.service';
import { TokenService } from '../token/token.service';
import { SecurityLogService } from '../security/security-log.service';
import { Request as ExpressRequest } from 'express';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';

// Serviço responsável pela autenticação de usuários
@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private encryption: EncryptionService,
    private tokenService: TokenService,
    private securityLogService: SecurityLogService,
    private jwtService: JwtService,
  ) {}

  // Realiza o login do usuário, verificando credenciais e 2FA se necessário
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
      // Se 2FA estiver ativo, retorna token temporário
      if (user.twoFactorEnabled && user.twoFactorVerified) {
        const tempToken = this.jwtService.sign(
          { sub: user.id, temp: true },
          { expiresIn: '5m' },
        );
        return { tempToken };
      }

      // Gera par de tokens e registra login bem sucedido
      const tokens = await this.tokenService.generateTokenPair(user.id);
      await this.securityLogService.logSuccessfulLogin(user.id, request);
      return tokens;
    } catch (error) {
      console.error('Login error:', error);
      throw new UnauthorizedException('Authentication failed');
    }
  }

  // Realiza o logout do usuário, invalidando todos os seus tokens
  async logout(token: string, request: ExpressRequest) {
    try {
      // Decodifica o token para obter o ID do usuário
      const decoded = this.jwtService.decode(token);

      // Invalida todos os tokens ativos do usuário
      if (decoded && typeof decoded === 'object' && decoded.sub) {
        await this.prisma.token.updateMany({
          where: {
            userId: decoded.sub,
            blacklisted: false,
          },
          data: { blacklisted: true },
        });
      }

      // Adiciona o token atual à blacklist
      await this.tokenService.blacklistToken(token);

      // Registra o logout nos logs de segurança
      await this.securityLogService.logLogout(request);

      return { message: 'Logged out successfully' };
    } catch (error) {
      console.error('Logout error:', error);
      return { message: 'Logged out successfully' };
    }
  }
}
