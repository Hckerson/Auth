import 'dotenv/config'
import { AppModule } from './app.module';
import { NestFactory } from '@nestjs/core';
import * as cookieParser from 'cookie-parser';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';


async function bootstrap() {

  const app = await NestFactory.create(AppModule);
  app.use(cookieParser(process.env.COOKIE_SECRET))
    const config = new DocumentBuilder()
    .setTitle('Auth API')
    .setDescription('The authentication endpoints')
    .setVersion('1.0')
    .addCookieAuth('sessionId') // optional
    .build();

  const document = SwaggerModule.createDocument(app, config);

  SwaggerModule.setup('api', app, document);
  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
