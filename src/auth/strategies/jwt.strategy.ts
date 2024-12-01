import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private prisma: PrismaService) {
    // Configura as opções da estratégia JWT
    super({
      // Define que o token será extraído do cabeçalho Authorization como Bearer token
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      // Não ignora a expiração do token - tokens expirados serão rejeitados
      ignoreExpiration: false,
      // Define a chave secreta para validar a assinatura do token
      secretOrKey: process.env.JWT_SECRET || 'your-secret-key',
    });
  }

  async validate(payload: any) {
    // Busca o usuário no banco de dados pelo ID contido no token
    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
    });

    // Se o usuário não existir, lança uma exceção
    if (!user) {
      throw new UnauthorizedException();
    }

    // Retorna os dados do usuário que serão anexados ao request
    return { userId: user.id, email: user.email };
  }
}
