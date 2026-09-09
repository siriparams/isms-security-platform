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


  // Login
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
      const response = await fetch('http://127.0.0.1:5000/login', {
        method: 'POST',

        headers: {
          'Content-Type': 'application/json'
        },

        body: JSON.stringify({
          username: username,
          password: password
        })
      });


      const data = await response.json();


      if (response.ok) {

        // Login successful
        this.isLoggedIn = true;

        alert('Login successful!');

        // Get assets from PostgreSQL through Flask
        await this.getAssets();

      } else {

        alert(data.message);

      }

    } catch (error) {

      alert('Cannot connect to backend');

      console.error(error);

    }
  }


  // Get assets from Flask
  async getAssets() {

    try {

      const response = await fetch(
        'http://127.0.0.1:5000/assets'
      );


      if (response.ok) {

        this.assets = await response.json();

        console.log('Assets:', this.assets);

      } else {

        console.error('Failed to get assets');

      }

    } catch (error) {

      console.error(
        'Cannot connect to backend',
        error
      );

    }
  }


  // Logout
  logout() {

    this.isLoggedIn = false;

    this.assets = [];

  }

}