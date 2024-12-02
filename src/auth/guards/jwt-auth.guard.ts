import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ExecutionContext } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../prisma/prisma.service';
import { Request } from 'express';

// Guarda de autenticação JWT que verifica tokens de acesso
@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(
    private jwtService: JwtService,
    private prisma: PrismaService,
  ) {
    super();
  }

  // Verifica se a requisição pode prosseguir baseado no token JWT
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);

    if (!token) {
      throw new UnauthorizedException('No token provided');
    }

    try {
      // Verifica e decodifica o token JWT
      const payload = await this.jwtService.verifyAsync(token);
      request.user = { userId: payload.sub };
      return true;
    } catch (error) {
      throw new UnauthorizedException('Invalid token');
    }
  }

  // Extrai o token do cabeçalho Authorization
  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers['authorization']?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }

  // Manipula erros de autenticação e retorna o usuário se válido
  handleRequest(err: any, user: any, info: any) {
    if (err || !user) {
      throw err || new UnauthorizedException('Invalid token');
    }
    return user;
  }
}
