import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import * as sanitizeHtml from 'sanitize-html';

@Injectable()
export class SanitizeInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    this.sanitizeRequest(request.body);

    return next.handle().pipe(
      map((data) => {
        return this.sanitizeResponse(data);
      }),
    );
  }

  private sanitizeRequest(data: any): void {
    if (data) {
      Object.keys(data).forEach((key) => {
        if (typeof data[key] === 'string') {
          data[key] = sanitizeHtml(data[key], {
            allowedTags: [],
            allowedAttributes: {},
          });
        }
      });
    }
  }

  private sanitizeResponse(data: any): any {
    if (data && typeof data === 'object') {
      Object.keys(data).forEach((key) => {
        if (typeof data[key] === 'string') {
          data[key] = sanitizeHtml(data[key], {
            allowedTags: [],
            allowedAttributes: {},
          });
        }
      });
    }
    return data;
  }
}
