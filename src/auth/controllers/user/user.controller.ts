import {
  Controller,
  Post,
  Body,
  Req,
  HttpCode,
  HttpStatus,
  UseGuards,
  UnauthorizedException,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBody,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { Request as ExpressRequest } from 'express';
import { RegisterDto } from './dto/register.dto';
import { Verify2FADto } from './dto/verify-2fa.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { UserService } from './user.service';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { JwtAuthGuard } from '../../guards/jwt-auth.guard';
import { CurrentUser } from '../../../common/decorators/current-user.decorator';
import { AppLogger } from 'src/common/logger/app.logger';
import { UserPayload } from 'src/auth/types';

@ApiTags('User Management')
@Controller('api/user')
export class UserController {
  private readonly CONTEXT = 'UserController';
  private readonly logger = AppLogger.forContext(this.CONTEXT);

  constructor(private readonly userService: UserService) {}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Registrar novo usuário',
    description: `
      Endpoint para criar uma nova conta de usuário no sistema.
      
      Fluxo:
      1. Valida os dados de entrada (nome, email, senha)
      2. Verifica se o email já está em uso
      3. Cria o usuário com senha criptografada
      4. Envia email de verificação
      
      Requisitos de senha:
      - Mínimo 8 caracteres
      - Pelo menos 1 letra maiúscula
      - Pelo menos 1 letra minúscula  
      - Pelo menos 1 número
      
      Retorno:
      - ID do usuário criado
      - Email cadastrado
      - Nome do usuário
    `,
  })
  @ApiBody({ type: RegisterDto })
  @ApiResponse({
    status: 201,
    description: 'Usuário registrado com sucesso',
    schema: {
      example: {
        id: 1,
        email: 'matheuscastroks@gmail.com',
        name: 'Matheus Castro',
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Dados inválidos ou email já cadastrado',
  })
  async register(@Body() dto: RegisterDto, @Req() request: ExpressRequest) {
    this.logger.log(`Registration attempt - Email: ${dto.email}`, this.CONTEXT);
    try {
      this.logger.debug(`Client info - IP: ${request.ip}`, this.CONTEXT);
      const result = await this.userService.register(dto, request);
      this.logger.log(
        `User registered successfully - ID: ${result.id}`,
        this.CONTEXT,
      );
      return result;
    } catch (error) {
      this.logger.error(
        `Registration failed for ${dto.email}`,
        error.stack,
        this.CONTEXT,
      );
      throw error;
    }
  }

  @Post('2fa/verify')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Verificar código 2FA',
    description: `
      Endpoint para validar o código de autenticação de dois fatores.
      
      Fluxo:
      1. Recebe código 2FA e token temporário
      2. Valida o código com o segredo do usuário
      3. Se válido, gera novos tokens de acesso
      
      Uso:
      - Durante login quando 2FA está ativo
      - Para confirmar ativação do 2FA
      
      Retorno:
      - Token de acesso
      - Token de atualização
    `,
  })
  @ApiBody({ type: Verify2FADto })
  @ApiResponse({
    status: 200,
    description: 'Verificação 2FA bem sucedida',
    schema: {
      example: {
        accessToken: 'jwt.token.access',
        refreshToken: 'jwt.token.refresh',
      },
    },
  })
  @ApiResponse({ status: 401, description: 'Código 2FA inválido' })
  async verify2FA(@Body() dto: Verify2FADto, @Req() request: ExpressRequest) {
    this.logger.log('2FA verification attempt', this.CONTEXT);
    try {
      this.logger.debug(
        'Decoding temp token for 2FA verification',
        this.CONTEXT,
      );
      const result = await this.userService.verify2FA(dto, request);
      this.logger.log('2FA verification successful', this.CONTEXT);
      return result;
    } catch (error) {
      this.logger.error('2FA verification failed', error.stack, this.CONTEXT);
      throw error;
    }
  }

  @Post('password/forgot')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Solicitar redefinição de senha',
    description: `
      Endpoint para iniciar o processo de recuperação de senha.
      
      Fluxo:
      1. Verifica se email existe
      2. Gera token único de redefinição
      3. Envia email com instruções e link
      4. Link expira em 1 hora
      
      Segurança:
      - Não revela se email existe na base
      - Rate limiting por IP
      - Token único por solicitação
      - Expiração automática do token
    `,
  })
  @ApiBody({ type: ForgotPasswordDto })
  @ApiResponse({
    status: 200,
    description: 'Instruções enviadas com sucesso',
    schema: {
      example: {
        message: 'Instruções de redefinição enviadas para seu email',
      },
    },
  })
  @ApiResponse({ status: 404, description: 'Usuário não encontrado' })
  async forgotPassword(@Body() dto: ForgotPasswordDto) {
    this.logger.log(`Password reset requested for: ${dto.email}`, this.CONTEXT);
    try {
      const result = await this.userService.forgotPassword(dto);
      this.logger.log(
        `Password reset email sent to: ${dto.email}`,
        this.CONTEXT,
      );
      return { message: result.message };
    } catch (error) {
      this.logger.error(
        `Password reset failed for ${dto.email}`,
        error.stack,
        this.CONTEXT,
      );
      throw error;
    }
  }

  @Post('password/reset')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Redefinir senha',
    description: `
      Endpoint para concluir o processo de redefinição de senha.
      
      Fluxo:
      1. Valida token de redefinição
      2. Verifica requisitos da nova senha
      3. Atualiza senha do usuário
      4. Invalida token usado
      5. Envia notificação de alteração
      
      Requisitos senha:
      - Mínimo 8 caracteres
      - Pelo menos 1 maiúscula
      - Pelo menos 1 minúscula
      - Pelo menos 1 número
      
      Segurança:
      - Token de uso único
      - Expiração em 1 hora
      - Invalidação após uso
    `,
  })
  @ApiBody({ type: ResetPasswordDto })
  @ApiResponse({
    status: 200,
    description: 'Senha redefinida com sucesso',
    schema: {
      example: {
        message: 'Senha alterada com sucesso',
      },
    },
  })
  @ApiResponse({ status: 400, description: 'Token inválido ou expirado' })
  async resetPassword(@Body() dto: ResetPasswordDto) {
    this.logger.log('Password reset attempt', this.CONTEXT);
    try {
      this.logger.debug('Validating reset token', this.CONTEXT);
      const result = await this.userService.resetPassword(dto);
      this.logger.log('Password reset successful', this.CONTEXT);
      return result;
    } catch (error) {
      this.logger.error('Password reset failed', error.stack, this.CONTEXT);
      throw error;
    }
  }

  @Post('verify-email')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Verificar email',
    description: `
      Endpoint para confirmar o email do usuário.
      
      Fluxo:
      1. Valida código de verificação
      2. Marca email como verificado
      3. Atualiza status da conta
      4. Libera funcionalidades restritas
      
      Importante:
      - Código expira em 24h
      - Email verificado é requisito para:
        * Login no sistema
        * Alteração de senha
        * Ativação de 2FA
    `,
  })
  @ApiBody({ type: VerifyEmailDto })
  @ApiResponse({
    status: 200,
    description: 'Email verificado com sucesso',
  })
  @ApiResponse({ status: 400, description: 'Código de verificação inválido' })
  async verifyEmail(@Body() dto: VerifyEmailDto) {
    return this.userService.verifyEmail(dto);
  }

  @Post('2fa/enable')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Habilitar 2FA',
    description: `
      Endpoint para iniciar a configuração de autenticação de dois fatores.
      
      Fluxo:
      1. Gera segredo único TOTP
      2. Cria QR code para app autenticador
      3. Aguarda confirmação via /2fa/confirm
      4. 2FA fica pendente até confirmação
      
      Retorno:
      - secret: Código secreto para backup
      - qrCode: QR code em base64
      
      Importante:
      - Guardar código secreto com segurança
      - Usar Google Authenticator ou similar
      - Confirmar setup em até 10 minutos
      - Email deve estar verificado
    `,
  })
  @ApiResponse({
    status: 200,
    description: 'QR code gerado com sucesso',
    schema: {
      properties: {
        secret: {
          type: 'string',
          description: 'Código secreto para backup',
        },
        qrCode: {
          type: 'string',
          description: 'QR code em base64',
        },
      },
    },
  })
  async enable2FA(@CurrentUser() user: UserPayload) {
    if (!user?.userId) {
      throw new UnauthorizedException('User ID is required');
    }

    this.logger.log(
      `2FA enable attempt - User ID: ${user.userId}`,
      this.CONTEXT,
    );
    try {
      const result = await this.userService.enable2FA(user.userId);
      this.logger.log(
        `2FA enabled successfully for user ${user.userId}`,
        this.CONTEXT,
      );
      return result;
    } catch (error) {
      this.logger.error(
        `2FA enable failed for user ${user.userId}`,
        error.stack,
        this.CONTEXT,
      );
      throw error;
    }
  }

  @Post('2fa/confirm')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Confirmar 2FA',
    description: `
      Endpoint para finalizar a configuração do 2FA.
      
      Fluxo:
      1. Valida código do app autenticador
      2. Ativa 2FA na conta se código correto
      3. Habilita requisito de 2FA para login
      
      Importante:
      - Usar código do app autenticador
      - Setup deve ser concluído em 10 min
      - Após ativação, 2FA será exigido em:
        * Login
        * Operações sensíveis
        * Alterações de segurança
    `,
  })
  @ApiBody({ type: Verify2FADto })
  @ApiResponse({
    status: 200,
    description: '2FA ativado com sucesso',
  })
  async confirm2FA(
    @CurrentUser() user: UserPayload,
    @Body() dto: Verify2FADto,
  ) {
    if (!user?.userId) {
      throw new UnauthorizedException('User ID is required');
    }

    this.logger.log(
      `2FA confirmation attempt - User ID: ${user.userId}`,
      this.CONTEXT,
    );
    try {
      const result = await this.userService.confirm2FA(user.userId, dto.code);
      this.logger.log(
        `2FA confirmed successfully for user ${user.userId}`,
        this.CONTEXT,
      );
      return result;
    } catch (error) {
      this.logger.error(
        `2FA confirmation failed for user ${user.userId}`,
        error.stack,
        this.CONTEXT,
      );
      throw error;
    }
  }
}
