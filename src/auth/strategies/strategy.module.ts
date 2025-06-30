import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { PassportModule } from '@nestjs/passport';
import { PrismaService } from 'src/prisma/prisma.service';

@Module({
  imports:[ConfigModule, PassportModule],
  controllers: [],
  providers: [PrismaService],
})
export class AuthModule {}
