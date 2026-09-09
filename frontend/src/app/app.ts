import { Component } from '@angular/core';

@Component({
  selector: 'app-root',
  templateUrl: './app.html',
  styleUrl: './app.css'
})
export class App {

  async login(event: Event) {
    event.preventDefault();

    const form = event.target as HTMLFormElement;

    const username = (form.elements.namedItem('username') as HTMLInputElement).value;
    const password = (form.elements.namedItem('password') as HTMLInputElement).value;

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
        alert('Login successful!');
      } else {
        alert(data.message);
      }

    } catch (error) {
      alert('Cannot connect to backend');
      console.error(error);
    }
  }
}