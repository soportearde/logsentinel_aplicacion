import { Component, inject, computed } from '@angular/core';
import { RouterOutlet, RouterLink, RouterLinkActive } from '@angular/router';
import { AuthService } from '../core/services/auth.service';

@Component({
  selector: 'app-layout',
  imports: [RouterOutlet, RouterLink, RouterLinkActive],
  templateUrl: './layout.html',
  styleUrl: './layout.scss'
})
export class LayoutComponent {
  auth = inject(AuthService);
  user = this.auth.currentUser;

  initials = computed(() => {
    const name = this.user()?.name ?? '';
    return name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2);
  });

  isAdmin = computed(() => this.auth.isAdmin());
  isAnalyst = computed(() => this.auth.isAnalyst());

  logout() {
    this.auth.logout();
  }
}
