import {
  Injectable,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../prisma/prisma.service';

/**
 * Guarda de autenticação JWT
 *
 * Esta guarda é responsável por:
 * - Validar tokens JWT em requisições protegidas
 * - Verificar se o token está na blacklist
 * - Verificar se o token não está expirado
 * - Extrair e validar o payload do token
 */
@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(
    private jwtService: JwtService, // Serviço para manipulação de tokens JWT
    private prisma: PrismaService, // Serviço de acesso ao banco de dados
  ) {
    super();
  }

  /**
   * Valida se a requisição pode prosseguir baseado no token JWT
   * @param context - Contexto da execução contendo os dados da requisição
   * @returns true se o token for válido, lança exceção caso contrário
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);

    // Verifica se o token foi fornecido
    if (!token) {
      throw new UnauthorizedException('No token provided');
    }

    try {
      // Verifica a assinatura e validade do token
      const payload = await this.jwtService.verifyAsync(token);

      // Busca o registro do token no banco de dados
      const tokenRecord = await this.prisma.token.findFirst({
        where: {
          token,
          blacklisted: false, // Verifica se não está na blacklist
          expires: { gt: new Date() }, // Verifica se não está expirado
        },
      });

      // Se o token não for encontrado ou estiver inválido
      if (!tokenRecord) {
        throw new UnauthorizedException('Invalid or expired token');
      }

      // Adiciona os dados do usuário à requisição
      request.user = payload;
      return true;
    } catch {
      throw new UnauthorizedException('Invalid token');
    }
  }

  /**
   * Extrai o token JWT do cabeçalho Authorization
   * @param request - Objeto de requisição HTTP
   * @returns Token JWT ou undefined se não encontrado
   */
  private extractTokenFromHeader(request: any): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
