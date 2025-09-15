import { Test, TestingModule } from '@nestjs/testing';
import { TekcifyService } from './tekcify.service';

describe('TekcifyService', () => {
  let service: TekcifyService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [TekcifyService],
    }).compile();

    service = module.get<TekcifyService>(TekcifyService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
