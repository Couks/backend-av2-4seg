import { Controller, Get, Redirect } from '@nestjs/common';

@Controller()
export class AppController {
  @Get()
  @Redirect('/api/docs')
  redirectToDocs() {
    // Este método será chamado quando a rota raiz (/) for acessada
    // O decorador @Redirect automaticamente redirecionará para /api/docs
  }
}
