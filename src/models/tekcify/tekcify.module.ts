import { Module } from '@nestjs/common';
import { TekcifyService } from './tekcify.service';
import { TekcifyController } from './tekcify.controller';

@Module({
  controllers: [TekcifyController],
  providers: [TekcifyService],
})
export class TekcifyModule {}
