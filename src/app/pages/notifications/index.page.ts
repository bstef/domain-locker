import { Component } from '@angular/core';

import { PrimeNgModule } from '~/app/prime-ng.module';
import { NotificationsListComponent } from '~/app/components/notifications-list/notifications-list.component';

@Component({
  standalone: true,
  templateUrl: './index.page.html',
  imports: [PrimeNgModule, NotificationsListComponent],
})
export default class NotificationsPage {}
