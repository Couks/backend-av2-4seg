import {
  Controller,
  Post,
  Get,
  Headers,
  Req,
  HttpCode,
  HttpStatus,
  UnauthorizedException,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiHeader,
} from '@nestjs/swagger';
import { Request } from 'express';
import { TokenService } from './token.service';
import { AppLogger } from 'src/common/logger/app.logger';

@ApiTags('Token Management')
@Controller('api/token')
export class TokenController {
  private readonly CONTEXT = 'TokenController';
  private readonly logger = AppLogger.forContext(this.CONTEXT);

  constructor(private readonly tokenService: TokenService) {}

  @Get('refresh')
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Atualizar access token',
    description: `
      Gera um novo access token usando um refresh token válido.
      
      Sistema de tokens:
      - Access Token: Token de curta duração (15min) usado para autenticar requisições
      - Refresh Token: Token de longa duração (7 dias) usado para obter novos access tokens
      
      Fluxo:
      1. Cliente envia refresh token no header Authorization
      2. Servidor valida refresh token
      3. Se válido, gera e retorna novo access token
      4. Cliente usa novo access token para requisições
      
      Uso no frontend:
      - Guardar access token e refresh token após login
      - Usar access token no header Authorization
      - Quando access token expirar (401), usar este endpoint para obter novo
    `,
  })
  @ApiHeader({
    name: 'Authorization',
    description:
      'Bearer refresh_token - O refresh token deve ser enviado com o prefixo "Bearer "',
    required: true,
    schema: {
      type: 'string',
      example: 'Bearer eyJhbGciOiJIUzI1NiIs...',
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Novo access token gerado com sucesso',
    schema: {
      properties: {
        accessToken: {
          type: 'string',
          description: 'Novo token de acesso para autenticação de requisições',
          example: 'eyJhbGciOiJIUzI1NiIs...',
        },
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: 'Refresh token inválido, expirado ou na blacklist',
  })
  async refreshToken(
    @Headers('authorization') auth: string,
    @Req() request: Request,
  ) {
    this.logger.log(`Token refresh attempt - IP: ${request.ip}`, this.CONTEXT);
    try {
      if (!auth?.startsWith('Bearer ')) {
        this.logger.warn('Invalid token format in refresh attempt');
        throw new UnauthorizedException('Invalid token format');
      }

      const token = auth.split(' ')[1];
      this.logger.debug('Token validation started', this.CONTEXT);
      const result = await this.tokenService.refreshToken(token, request);
      this.logger.log('Token refresh successful', this.CONTEXT);
      return result;
    } catch (error) {
      this.logger.error(
        `Token refresh failed: ${error.message}`,
        error.stack,
        this.CONTEXT,
      );
      throw error;
    }
  }

  @Post('validate')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Validar token JWT',
    description: `
      Verifica se um token JWT (access ou refresh) é válido.
      
      Validações realizadas:
      1. Token é um JWT válido
      2. Token não está expirado
      3. Para refresh tokens: verifica se está na blacklist
      4. Para access tokens: apenas valida a assinatura
      
      Uso:
      - Frontend pode usar para verificar validade de tokens
      - Útil para verificar se precisa renovar tokens
      - Pode validar tanto access quanto refresh tokens
    `,
  })
  @ApiHeader({
    name: 'Authorization',
    description:
      'Bearer token - O token JWT a ser validado (access ou refresh)',
    required: true,
  })
  @ApiResponse({
    status: 200,
    description: 'Resultado da validação do token',
    schema: {
      properties: {
        valid: {
          type: 'boolean',
          description: 'Indica se o token é válido',
        },
        payload: {
          type: 'object',
          description: 'Payload do token se válido',
          properties: {
            sub: {
              type: 'number',
              description: 'ID do usuário',
            },
            type: {
              type: 'string',
              description: 'Tipo do token (access/refresh)',
              enum: ['access', 'refresh'],
            },
            exp: {
              type: 'number',
              description: 'Timestamp de expiração',
            },
          },
        },
      },
    },
  })
  async validateToken(@Headers('authorization') auth: string) {
    this.logger.log('Token validation request received', this.CONTEXT);
    try {
      if (!auth?.startsWith('Bearer ')) {
        this.logger.warn('Invalid token format in validation attempt');
        return { valid: false, message: 'Invalid token format' };
      }

      const token = auth.split(' ')[1];
      this.logger.debug('Starting token validation process', this.CONTEXT);
      const result = await this.tokenService.validateToken(token);
      this.logger.log(`Token validation result: ${result.valid}`, this.CONTEXT);
      return result;
    } catch (error) {
      this.logger.error('Token validation failed', error.stack, this.CONTEXT);
      return { valid: false, message: error.message };
    }
  }

  private maskToken(token: string): string {
    if (!token) return 'null';
    return `${token.substring(0, 10)}...${token.substring(token.length - 10)}`;
  }
}
