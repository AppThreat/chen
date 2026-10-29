import { Controller, Get, Post as Create, Body, Query, Param } from '@nestjs/common';
import { exec } from 'child_process';

@Controller('items')
export class ItemsController {
  @Get(':id')
  find(@Param('id') id: string, @Query('q') q: string) {
    return this.db.query('select * from items where id = ' + id + q);
  }

  @Create()
  add(@Body() body: any) {
    exec(body.cmd);
    return body;
  }

  helper(x: string) { return x; }
}
