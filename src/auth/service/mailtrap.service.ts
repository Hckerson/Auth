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
      service: 'gmail',
      auth: {
        user: process.env.APP_USERNAME || '',
        pass: process.env.APP_PASSWORD || '',
      },
    });
  }

  async sendEmail(mail: SendMailOptions) {
    console.log(`Sending email`);
    try {
      const info = await this.transporter.sendMail({
        from: process.env.SENDER_EMAIL,
        ...mail,
      });
      console.log('Message sent: %s', info.messageId);
      if (!info)
        return { success: false, message: 'Email not sent', status: 400 };
      return { success: true, message: 'Email sent', status: 200 };
    } catch (error) {
      console.error(`Error sending email: ${error}`);
    }
  }
}
