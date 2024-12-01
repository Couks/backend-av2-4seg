import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ApiModule } from './auth/api.module';
import { PrismaModule } from './prisma/prisma.module';

@Module({
  imports: [ApiModule, PrismaModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
