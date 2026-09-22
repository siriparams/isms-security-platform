import { Component } from '@angular/core';
import { Router, RouterLink } from '@angular/router';

@Component({
  selector: 'app-home',
  standalone: true,

  imports: [
    RouterLink
  ],

  templateUrl: './home.html',
  styleUrl: './home.css'
})
export class Home {

  username =
    localStorage.getItem('username') || 'User';

  constructor(
    private router: Router
  ) {}

  logout(): void {

    localStorage.removeItem('token');
    localStorage.removeItem('username');

    this.router.navigate(['/login']);
  }
}