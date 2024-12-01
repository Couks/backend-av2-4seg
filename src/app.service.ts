import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  getHello(): string {
    return 'Api de autenticação - Avaliação 2: Disciplina de Segurança da Informação';
  }
}
