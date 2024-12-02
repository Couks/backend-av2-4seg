import { Module } from '@nestjs/common';
import { ApiModule } from './auth/api.module';
import { PrismaModule } from './prisma/prisma.module';
import { LoggerModule } from './common/logger/logger.module';

@Module({
  imports: [ApiModule, PrismaModule, LoggerModule],
})
export class AppModule {}
