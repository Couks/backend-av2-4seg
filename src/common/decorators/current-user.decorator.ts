import {
  createParamDecorator,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';

// Decorator para obter o usuário atual da requisição
export const CurrentUser = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    // Obtém o objeto de requisição do contexto HTTP
    const request = ctx.switchToHttp().getRequest();

    // Verifica se existe um usuário com ID na requisição
    if (!request.user?.userId) {
      throw new UnauthorizedException('User not found in request');
    }

    // Retorna o objeto do usuário
    return request.user;
  },
);
