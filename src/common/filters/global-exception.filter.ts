import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Response } from 'express';

// Filtro global para capturar e tratar todas as exceções da aplicação
@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  // Método que captura e processa as exceções
  catch(exception: unknown, host: ArgumentsHost) {
    // Obtém o contexto HTTP da requisição
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    // Define valores padrão para status e mensagem
    let status = HttpStatus.INTERNAL_SERVER_ERROR;
    let message = 'Internal server error';

    // Se for uma exceção HTTP conhecida, usa seus valores específicos
    if (exception instanceof HttpException) {
      status = exception.getStatus();
      message = exception.message;
    }

    // Retorna a resposta formatada com os detalhes do erro
    response.status(status).json({
      statusCode: status,
      message,
      timestamp: new Date().toISOString(),
      path: request.url,
    });
  }
}
