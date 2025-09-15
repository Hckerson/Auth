import { Test, TestingModule } from '@nestjs/testing';
import { TekcifyController } from './tekcify.controller';
import { TekcifyService } from './tekcify.service';

describe('TekcifyController', () => {
  let controller: TekcifyController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [TekcifyController],
      providers: [TekcifyService],
    }).compile();

    controller = module.get<TekcifyController>(TekcifyController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
