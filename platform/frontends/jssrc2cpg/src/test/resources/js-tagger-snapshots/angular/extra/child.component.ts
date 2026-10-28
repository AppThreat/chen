import { Component, Input } from '@angular/core';

@Component({ selector: 'app-child', template: '<p [innerHTML]="label"></p>' })
export class ChildComponent {
  @Input() label: string = '';
  @Input('title') heading: string = '';
}
