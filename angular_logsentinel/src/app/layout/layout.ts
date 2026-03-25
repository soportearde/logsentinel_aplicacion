import { Component, inject, computed, OnInit } from '@angular/core';
import { RouterOutlet, RouterLink, RouterLinkActive } from '@angular/router';
import { AuthService } from '../core/services/auth.service';
import { BackgroundSyncService } from '../core/services/background-sync.service';

@Component({
  selector: 'app-layout',
  imports: [RouterOutlet, RouterLink, RouterLinkActive],
  templateUrl: './layout.html',
  styleUrl: './layout.scss'
})
export class LayoutComponent implements OnInit {
  private auth   = inject(AuthService);
  private bgSync = inject(BackgroundSyncService);

  user = this.auth.currentUser;

  initials = computed(() => {
    const name = this.user()?.name ?? '';
    return name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2);
  });

  isAdmin = computed(() => this.auth.isAdmin());
  isAnalyst = computed(() => this.auth.isAnalyst());

  ngOnInit() {
    // Si el usuario ya tiene sesión (recarga de página), arrancamos la sincronización
    if (this.auth.isLoggedIn()) {
      this.bgSync.start();
    }
  }

  logout() {
    this.auth.logout();
  }
}