import { Module } from '@nestjs/common';
import { SecurityController } from './security.controller';
import { SecurityLogService } from './security-log.service';
import { PrismaModule } from 'src/prisma/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [SecurityController],
  providers: [SecurityLogService],
  exports: [SecurityLogService],
})
export class SecurityModule {}
