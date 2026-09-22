import { CommonModule } from '@angular/common';
import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';

@Component({
  selector: 'app-login',
  standalone: true,

  imports: [
    FormsModule,
    CommonModule
  ],

  templateUrl: './login.html',
  styleUrl: './login.css'
})
export class Login {

  username = '';
  password = '';

  loginError = '';
  loading = false;

  private apiUrl = 'http://127.0.0.1:5000';

  constructor(
    private http: HttpClient,
    private router: Router
  ) {}

  login(): void {

    this.loginError = '';

    if (!this.username || !this.password) {

      this.loginError =
        'Please enter username and password.';

      return;
    }

    this.loading = true;

    this.http.post<any>(
      `${this.apiUrl}/login`,
      {
        username: this.username,
        password: this.password
      }
    ).subscribe({

      next: (response) => {

        this.loading = false;

        if (response.success && response.token) {

          localStorage.setItem(
            'token',
            response.token
          );

          localStorage.setItem(
            'username',
            this.username
          );

          this.router.navigate(['/home']);

        } else {

          this.loginError =
            response.message ||
            'Login failed.';
        }
      },

      error: (error) => {

        this.loading = false;

        if (error.status === 401) {

          this.loginError =
            'Invalid username or password.';

        } else if (error.status === 0) {

          this.loginError =
            'Cannot connect to Flask server.';

        } else {

          this.loginError =
            error.error?.message ||
            'Login failed.';
        }
      }
    });
  }
}