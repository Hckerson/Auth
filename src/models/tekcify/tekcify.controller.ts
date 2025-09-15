import { Controller, Get, Post, Body, Patch, Param, Delete } from '@nestjs/common';
import { TekcifyService } from './tekcify.service';

@Controller('tekcify')
export class TekcifyController {
  constructor(private readonly tekcifyService: TekcifyService) {}



  @Get('login')
  login() {     
    return this.tekcifyService.login();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.tekcifyService.findOne(+id);
  }

  @Patch(':id')
  update(@Param('id') id: string) {
    return this.tekcifyService.update(+id);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.tekcifyService.remove(+id);
  }
}
