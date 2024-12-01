import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import * as sanitizeHtml from 'sanitize-html';

/**
 * Interceptor para sanitização de dados
 *
 * Este interceptor é responsável por:
 * - Sanitizar dados de entrada (request) removendo tags HTML maliciosas
 * - Sanitizar dados de saída (response) removendo tags HTML maliciosas
 * - Prevenir ataques XSS (Cross-Site Scripting)
 */
@Injectable()
export class SanitizeInterceptor implements NestInterceptor {
  /**
   * Intercepta a requisição para sanitizar dados
   * @param context - Contexto da execução contendo request/response
   * @param next - Handler para continuar o fluxo da requisição
   * @returns Observable com dados sanitizados
   */
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    // Sanitiza os dados do corpo da requisição
    this.sanitizeRequest(request.body);

    // Sanitiza os dados da resposta
    return next.handle().pipe(
      map((data) => {
        return this.sanitizeResponse(data);
      }),
    );
  }

  /**
   * Sanitiza os dados da requisição removendo tags HTML
   * @param data - Dados do corpo da requisição
   */
  private sanitizeRequest(data: any): void {
    if (data) {
      Object.keys(data).forEach((key) => {
        if (typeof data[key] === 'string') {
          // Remove todas as tags HTML e atributos do texto
          data[key] = sanitizeHtml(data[key], {
            allowedTags: [], // Não permite nenhuma tag HTML
            allowedAttributes: {}, // Não permite nenhum atributo
          });
        }
      });
    }
  }

  /**
   * Sanitiza os dados da resposta removendo tags HTML
   * @param data - Dados da resposta
   * @returns Dados sanitizados
   */
  private sanitizeResponse(data: any): any {
    if (data && typeof data === 'object') {
      Object.keys(data).forEach((key) => {
        if (typeof data[key] === 'string') {
          // Remove todas as tags HTML e atributos do texto
          data[key] = sanitizeHtml(data[key], {
            allowedTags: [], // Não permite nenhuma tag HTML
            allowedAttributes: {}, // Não permite nenhum atributo
          });
        }
      });
    }
    return data;
  }
}
