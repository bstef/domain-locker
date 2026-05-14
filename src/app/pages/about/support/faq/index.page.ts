import { Component } from '@angular/core';

import { PrimeNgModule } from '~/app/prime-ng.module';

@Component({
  selector: 'app-faq',
  standalone: true,
  imports: [PrimeNgModule],
  templateUrl: './index.page.html',
})
export default class FaqPage {}
