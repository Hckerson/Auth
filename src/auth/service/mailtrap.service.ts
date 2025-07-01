import 'dotenv/config';
import * as nodemailer from 'nodemailer';
import { SendMailOptions, Transporter } from 'nodemailer';
import { Injectable, OnModuleInit } from '@nestjs/common';

@Injectable()
export class Mailtrap implements OnModuleInit {
  private transporter: Transporter;

  constructor() {}

  onModuleInit() {
    this.transporter = nodemailer.createTransport({
      host: process.env.MAILTRAP_HOST || '',
      port: Number(process.env.MAILTRAP_PORT) || 587,
      auth: {
        user: process.env.MAILTRAP_USERNAME || '',
        pass: process.env.MAILTRAP_PASSWORD || '',
      },
    });
  }

  async sendEmail(mail: SendMailOptions) {
    try {
      const info = await this.transporter.sendMail({
        from: process.env.SENDER_EMAIL,
        ...mail,
      });
      console.log('Message sent: %s', info.messageId);
      return info;
    } catch (error) {
      console.error(`Error sending email: ${error}`);
    }
  }
}
