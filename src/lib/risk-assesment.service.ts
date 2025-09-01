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

  async getThreatLevel(loginDto: LoginDto, request: Request) {
    //get threat level
    const { ipAddress = '', email = '' } = loginDto;
    await this.geoipAssessment(ipAddress, email);
    await this.fingerprintingAccessment(request, email, ipAddress);
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
        },
      });
      console.log(`Found user ${user?.geoData}`);

      if (!user?.geoData) return this.threatLevel;

      const existingGeoData = user?.geoData;
      const {
        country: existingCountry,
        region: existingRegion,
        continent: existingContinent,
        city: existingCity,
      } = existingGeoData;

      if (state_prov !== existingRegion) this.threatLevel += 20;
      if (country_name !== existingCountry) this.threatLevel += 15;
      if (continent_name !== existingContinent) this.threatLevel += 25;
      if (city !== existingCity) this.threatLevel += 10;
      console.log(`Ending geoip assessment`);
      console.log(`Threat level: ${this.threatLevel}`);
      const geoData = user?.geoData;
      if (!geoData) {
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
      }
    } catch (error) {
      console.error(`Error finding geo data: ${error}`);
    }
  }

  async fingerprintingAccessment(
    request: Request,
    email: string,
    ipAddress: string,
  ) {
    //get device fingerPrint
    console.log(`Starting fingerprint accessment for ${email}`);
    const userAgent = request.headers['user-agent'] || '';
    const acceptLanguage = request.headers['accept-language'] || '';
    const fingerPrint = `${userAgent}-${acceptLanguage}-${ipAddress}`;
    const hash = createHash('sha256').update(fingerPrint).digest('hex');
    try {
      const user = await this.prisma.user.findUnique({
        where: {
          email: email,
        },
        select: {
          lastKnownDevice: true,
          lastLoginIp: true,
        },
      });
      if (!user) return;

      const { lastKnownDevice, lastLoginIp } = user;

      if (lastKnownDevice !== hash) this.threatLevel += 15;
      if (lastLoginIp !== ipAddress) this.threatLevel += 15;
      console.log(`Ending fingerprint accessment for ${email}`);
      console.log(`Threat level: ${this.threatLevel}`);
      try {
        await this.prisma.user.update({
          where: {
            email: email.toLowerCase(),
          },
          data: {
            lastKnownDevice: hash,
            lastLoginIp: ipAddress,
          },
        });
      } catch (error) {
        console.error(`Error updating login deets: ${error}`);
      }
    } catch (error) {
      console.error(`Error fetching user login deets: ${error}`);
    }
  }
}
