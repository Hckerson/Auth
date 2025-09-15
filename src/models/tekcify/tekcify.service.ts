import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { randomToken } from 'src/lib/utils';
import { Tekcify, SCOPES, RESPONSE_TYPES } from 'tekcify-auth';

@Injectable()
export class TekcifyService {
  private client: Tekcify;
  private clientId: string;
  private clientSecret: string;
  constructor(private readonly config: ConfigService) {
    ((this.clientId = this.config.get<string>('app.auth.tekcify.id') || ''),
      (this.clientSecret =
        this.config.get<string>('app.auth.tekcify.secret') || ''));

    if (!this.client) {
      this.client = new Tekcify(this.clientId, this.clientSecret);
    }
  }
  async login() {
    try {
      const loginResponse = await this.client.initializeLogin({
        redirectUrl: this.config.get<string>('app.auth.tekcify.callback'),
        scope: [SCOPES.EMAIL, SCOPES.PROFILE],
        responseType: RESPONSE_TYPES.CODE,
        state: randomToken(),
      });
      return loginResponse.data
      const loginUrl = loginResponse.data.loginUrl
    } catch (error) {
      console.error(error);
    }
  }

  findAll() {
    return `This action returns all tekcify`;
  }

  findOne(id: number) {
    return `This action returns a #${id} tekcify`;
  }

  update(id: number) {
    return `This action updates a #${id} tekcify`;
  }

  remove(id: number) {
    return `This action removes a #${id} tekcify`;
  }
}
