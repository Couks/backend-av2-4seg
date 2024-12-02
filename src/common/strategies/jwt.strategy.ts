import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

// Estratégia para validação de tokens JWT
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  // Configura a estratégia JWT com as opções necessárias
  constructor(private prisma: PrismaService) {
    super({
      // Extrai o token JWT do cabeçalho Authorization
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      // Não ignora tokens expirados
      ignoreExpiration: false,
      // Chave secreta para validar o token
      secretOrKey: process.env.JWT_SECRET,
    });
  }

  // Valida o payload do token JWT e retorna os dados do usuário
  async validate(payload: any) {
    // Busca o usuário no banco de dados usando o ID do payload
    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
    });

    // Se o usuário não existir, lança uma exceção
    if (!user) {
      throw new UnauthorizedException();
    }

    // Retorna os dados básicos do usuário
    return { userId: user.id, email: user.email };
  }
}
