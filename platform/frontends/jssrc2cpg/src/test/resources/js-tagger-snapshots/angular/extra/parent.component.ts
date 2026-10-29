import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

@Component({ selector: 'app-parent', template: '<app-child [label]="query" [title]="name"></app-child>' })
export class ParentComponent implements OnInit {
  query = '';
  name = 'static';
  constructor(private route: ActivatedRoute) {}
  ngOnInit() { this.query = this.route.snapshot.queryParams['q']; }
}
