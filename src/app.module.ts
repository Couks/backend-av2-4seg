import { Module } from '@nestjs/common';
import { ApiModule } from './auth/api.module';
import { PrismaModule } from './prisma/prisma.module';
import { LoggerModule } from './common/logger/logger.module';
import { AppController } from './app.controller';

@Module({
  imports: [ApiModule, PrismaModule, LoggerModule],
  controllers: [AppController],
})
export class AppModule {}
