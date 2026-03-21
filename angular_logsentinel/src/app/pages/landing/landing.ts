import { Component, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { AuthService } from '../../core/services/auth.service';

@Component({
  selector: 'app-landing',
  imports: [RouterLink],
  templateUrl: './landing.html',
  styleUrl: './landing.scss'
})
export class LandingPage {
  auth = inject(AuthService);
  isLoggedIn = this.auth.isLoggedIn();
}
