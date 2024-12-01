import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { PrismaService } from './prisma/prisma.service';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { ValidationPipe } from '@nestjs/common';
import { CustomValidationPipe } from './auth/pipes/validation.pipe';
import { SanitizeInterceptor } from './auth/interceptors/sanitize.interceptor';
import helmet from 'helmet';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Segurança básica
  app.use(helmet());
  app.enableCors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || 'http://localhost:3000',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    credentials: true,
  });

  // Validação e sanitização global
  app.useGlobalPipes(new CustomValidationPipe());
  app.useGlobalInterceptors(new SanitizeInterceptor());

  // Configuração do Swagger
  const config = new DocumentBuilder()
    .setTitle('Auth API')
    .setDescription('API de Autenticação com recursos de segurança')
    .setVersion('1.0')
    .addTag('Authentication')
    .addBearerAuth()
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document);

  const prismaService = app.get(PrismaService);

  await app.listen(3001);
}
bootstrap();
