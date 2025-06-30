import { AppModule } from './app.module';
import { NestFactory } from '@nestjs/core';
import * as cookieParser from 'cookie-parser';
import 'dotenv/config'


async function bootstrap() {

  const app = await NestFactory.create(AppModule);
  app.use(cookieParser(process.env.COOKIE_SECRET))
  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
