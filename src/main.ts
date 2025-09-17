import 'dotenv/config'
import { AppModule } from './app.module';
import { NestFactory } from '@nestjs/core';
import cookieParser from 'cookie-parser';
import * as session from 'express-session';
import { ConsoleLogger } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';


async function bootstrap() {

  const app = await NestFactory.create(AppModule,{
    logger: new ConsoleLogger({
      logLevels:['log', 'error', 'warn', 'debug', 'verbose'],
      prefix: 'Auth API', 
      json: true,
      colors: true
    })
  });
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
