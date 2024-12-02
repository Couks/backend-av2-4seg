import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import * as sanitizeHtml from 'sanitize-html';

// Interceptor que sanitiza dados de entrada e saída para prevenir XSS
@Injectable()
export class SanitizeInterceptor implements NestInterceptor {
  // Intercepta a requisição e sanitiza os dados
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    // Sanitiza o corpo da requisição
    this.sanitizeRequest(request.body);

    // Sanitiza a resposta
    return next.handle().pipe(
      map((data) => {
        return this.sanitizeResponse(data);
      }),
    );
  }

  // Remove tags HTML maliciosas dos dados da requisição
  private sanitizeRequest(data: any): void {
    if (data) {
      Object.keys(data).forEach((key) => {
        if (typeof data[key] === 'string') {
          data[key] = sanitizeHtml(data[key], {
            allowedTags: [], // Não permite tags HTML
            allowedAttributes: {}, // Não permite atributos
          });
        }
      });
    }
  }

  // Remove tags HTML maliciosas dos dados da resposta
  private sanitizeResponse(data: any): any {
    if (data && typeof data === 'object') {
      Object.keys(data).forEach((key) => {
        if (typeof data[key] === 'string') {
          data[key] = sanitizeHtml(data[key], {
            allowedTags: [], // Não permite tags HTML
            allowedAttributes: {}, // Não permite atributos
          });
        }
      });
    }
    return data;
  }
}
