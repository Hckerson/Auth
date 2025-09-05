import { Request } from 'express';
import { createHash } from 'crypto';
import { fetchLocation } from './services/maximind/ip';
import { Injectable } from '@nestjs/common';
import { LoginDto } from 'src/auth/dto/login-dto';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class RiskAssesmentService {
  threatLevel: number = 0;
  constructor(private readonly prisma: PrismaService) {}

  async riskLevel(loginDto: LoginDto, request: Request) {
    //get threat level
    const { email = '' } = loginDto;
    const ipAddress = '146.70.99.180';
    await this.geoipAssessment(ipAddress, email);
    await this.fingerprintingAccessment(request, email);
    return this.threatLevel;
  }

  async geoipAssessment(ipAddress: string, email: string) {
    try {
      const response = await fetchLocation(ipAddress);
      const locationData = response.location;
      const { state_prov, continent_name, country_name, city } = locationData;
      const user = await this.prisma.user.findFirst({
        where: {
          email: email,
        },
        select: {
          geoData: true,
          sessions: true,
        },
      });
      
      if (!user?.geoData) return this.threatLevel;
      if (!user?.sessions) return this.threatLevel;

      const sameProvince = state_prov == user.geoData.region;
      const sameCountry = country_name == user.geoData.country;
      const sameContinent = continent_name == user.geoData.continent;
      const sameCity = city == user.geoData.city;

      if (!sameCity) this.threatLevel += 10;
      if (!sameProvince) this.threatLevel += 15;
      if (!sameCountry) this.threatLevel += 20;
      if (!sameContinent) this.threatLevel += 25;
      try {
        await this.prisma.user.update({
          where: {
            email: email.toLowerCase(),
          },
          data: {
            geoData: {
              update: {
                region: state_prov,
                country: country_name,
                continent: continent_name,
                city,
              },
            },
          },
        });
      } catch (error) {
        console.error(`Error updating geo data: ${error}`);
      }
    } catch (error) {
      console.error(`Error finding geo data: ${error}`);
    }
  }

  async fingerprintingAccessment(request: Request, email: string) {
    const userAgent = request.headers['user-agent'] || '';
    const acceptLanguage = request.headers['accept-language'] || '';
    const fingerPrint = `${userAgent}-${acceptLanguage}`;
    const hash = createHash('sha256').update(fingerPrint).digest('hex');

    try {
      const sessions = await this.prisma.session.findFirst({
        where: {
          user: {
            email: email,
          },
        },
        orderBy: {
          createdAt: 'desc',
        },
        select: {
          uaString: true,
          devicePrint: true,
        },
      });
      if (!sessions) return this.threatLevel;
      const { uaString, devicePrint } = sessions;
      if (uaString != userAgent || devicePrint != hash) {
        this.threatLevel += 20;
      }
    } catch (error) {
      console.error(`Error fetching user login deets: ${error}`);
    }
  }
}
