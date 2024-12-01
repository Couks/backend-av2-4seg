import { Module } from '@nestjs/common';
import { SecurityController } from './security.controller';
import { SecurityLogService } from './security-log.service';

@Module({
  controllers: [SecurityController],
  providers: [SecurityLogService],
  exports: [SecurityLogService],
})
export class SecurityModule {}
