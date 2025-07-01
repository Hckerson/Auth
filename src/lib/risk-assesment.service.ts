import { Injectable } from '@nestjs/common';
import { RateLimiterMemory } from 'rate-limiter-flexible';

@Injectable()
export class RiskAssesmentService {
  private readonly options = {
    points: 6,
    duration: 1,
  };
  private rateLimiter = new RateLimiterMemory(this.options);
  private readonly threatLevel: number = 0;
  constructor() {

  }

  async rateLimit(ipAddress: string, ){
    try {
      
    } catch (error) {
      console.error(`Error rate limiting: ${error}`);
    }
  }
}
