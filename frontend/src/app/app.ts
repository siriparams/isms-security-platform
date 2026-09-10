import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-root',
  imports: [CommonModule],
  templateUrl: './app.html',
  styleUrl: './app.css'
})
export class App {

  // Stores assets received from Flask
  assets: any[] = [];

  // Controls whether login page or dashboard is displayed
  isLoggedIn = false;


  // =========================================================
  // LOGIN
  // =========================================================

  async login(event: Event) {

    event.preventDefault();

    const form = event.target as HTMLFormElement;

    const username = (
      form.elements.namedItem('username') as HTMLInputElement
    ).value;

    const password = (
      form.elements.namedItem('password') as HTMLInputElement
    ).value;


    try {

      const response = await fetch(
        'http://127.0.0.1:5000/login',
        {
          method: 'POST',

          headers: {
            'Content-Type': 'application/json'
          },

          body: JSON.stringify({
            username: username,
            password: password
          })
        }
      );


      const data = await response.json();


      // =====================================================
      // LOGIN SUCCESSFUL
      // =====================================================

      if (response.ok) {

        // Get JWT token returned by Flask
        const token = data.token;


        // Make sure JWT token was received
        if (!token) {

          alert(
            'Login successful, but JWT token was not received.'
          );

          return;
        }


        // Store JWT token in browser
        localStorage.setItem(
          'jwt_token',
          token
        );


        // Set login state
        this.isLoggedIn = true;


        alert('Login successful!');


        // Get protected assets
        await this.getAssets();

      }


      // =====================================================
      // LOGIN FAILED
      // =====================================================

      else {

        alert(data.message);

      }

    }


    // =======================================================
    // CONNECTION ERROR
    // =======================================================

    catch (error) {

      console.error(
        'Login error:',
        error
      );

      alert(
        'Cannot connect to backend'
      );

    }

  }


  // =========================================================
  // GET ALL ASSETS
  // =========================================================

  async getAssets() {

    try {

      // Get JWT token from browser
      const token = localStorage.getItem(
        'jwt_token'
      );


      // If JWT token does not exist
      if (!token) {

        console.error(
          'JWT token is missing'
        );

        this.isLoggedIn = false;

        return;
      }


      // Send JWT token to Flask
      const response = await fetch(
        'http://127.0.0.1:5000/assets',
        {
          method: 'GET',

          headers: {

            'Authorization': `Bearer ${token}`

          }

        }
      );


      // =====================================================
      // ASSETS SUCCESSFULLY RECEIVED
      // =====================================================

      if (response.ok) {

        this.assets = await response.json();


        console.log(
          'Assets:',
          this.assets
        );

      }


      // =====================================================
      // JWT INVALID OR EXPIRED
      // =====================================================

      else if (response.status === 401) {

        console.error(
          'JWT token is invalid or expired'
        );


        // Remove invalid JWT
        localStorage.removeItem(
          'jwt_token'
        );


        // Log user out
        this.isLoggedIn = false;

        this.assets = [];


        alert(
          'Your session has expired. Please login again.'
        );

      }


      // =====================================================
      // OTHER ERROR
      // =====================================================

      else {

        console.error(
          'Failed to get assets'
        );

      }

    }


    // =======================================================
    // CONNECTION ERROR
    // =======================================================

    catch (error) {

      console.error(
        'Cannot connect to backend:',
        error
      );

    }

  }


  // =========================================================
  // LOGOUT
  // =========================================================

  logout() {

    // Remove JWT token
    localStorage.removeItem(
      'jwt_token'
    );


    // Change login state
    this.isLoggedIn = false;


    // Clear assets
    this.assets = [];


    console.log(
      'Logged out successfully'
    );

  }

}