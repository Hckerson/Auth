import { User } from 'generated/prisma';
import { Strategy } from 'passport-oauth2';
import { AuthService } from '../auth.service';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';

@Injectable()
export class Oauth2Strategy extends PassportStrategy(Strategy) {
  //implement facebook strategy
  constructor(
    private authService: AuthService,
    private configService: ConfigService,
  ) {
    super({
      authorizationURL: configService.get<string>('AUTHORIZATION_URL') || '',
      tokenURL: configService.get<string>('TOKEN_URL') || '',
      clientID: configService.get<string>('GOOGLE_CLIENT_ID') || '',
      clientSecret: configService.get<string>('GOOGLE_CLIENT_SECRET') || '',
      callbackURL:configService.get<string>('CALLBACK_URL') || '' ,
    });
  }

  async validate(accessToken: string, refreshToken: string, profile: any) {
    console.log(profile)
    // const user = await this.authService.validateUser(profile);
    // if (!user) {
    //   throw new UnauthorizedException();
    // }
    // return user;
  }
}
