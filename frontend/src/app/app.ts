import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  HttpClient,
  HttpClientModule,
  HttpHeaders
} from '@angular/common/http';

interface Asset {
  id: number;
  hostname: string;
  ip_address: string | null;

  operating_system: any;
  hardware: any;
  network: any;
  software: any;
  management: any;
  security_posture: any;
  user_context: any;

  device_identity: any;
  host_identity: any;

  discovery_timestamp: string | null;
  platform: string | null;
  agent_version: string | null;
  created_at: string | null;

  // Allows the existing HTML to access any additional
  // asset property without TypeScript template errors.
  [key: string]: any;
}

@Component({
  selector: 'app-root',
  standalone: true,

  imports: [
    CommonModule,
    FormsModule,
    HttpClientModule
  ],

  templateUrl: './app.html',
  styleUrl: './app.css'
})
export class App implements OnInit {

  // =====================================================
  // BACKEND URL
  // =====================================================

  private apiUrl = 'http://127.0.0.1:5000';


  // =====================================================
  // LOGIN VARIABLES
  // =====================================================

  username = '';
  password = '';

  loginError = '';

  isLoggedIn = false;


  // =====================================================
  // ASSET VARIABLES
  // =====================================================

  assets: Asset[] = [];

  loadingAssets = false;

  assetError = '';


  // =====================================================
  // HTTP CLIENT
  // =====================================================

  constructor(
    private http: HttpClient
  ) {}


  // =====================================================
  // INITIALIZE APPLICATION
  // =====================================================

  ngOnInit(): void {

    const token = localStorage.getItem('token');

    const savedUsername =
      localStorage.getItem('username');


    if (token) {

      this.isLoggedIn = true;

      if (savedUsername) {

        this.username = savedUsername;
      }

      this.loadAssets();
    }
  }


  // =====================================================
  // LOGIN
  // =====================================================

  login(): void {

    this.loginError = '';


    // Check empty fields
    if (!this.username || !this.password) {

      this.loginError =
        'Please enter username and password.';

      return;
    }


    const loginData = {

      username: this.username,

      password: this.password
    };


    console.log('Sending login request...');


    this.http
      .post<any>(
        `${this.apiUrl}/login`,
        loginData
      )
      .subscribe({

        // -----------------------------------------------
        // LOGIN SUCCESS
        // -----------------------------------------------

        next: (response) => {

          console.log(
            'Login response:',
            response
          );


          if (response.success) {

            // Save JWT token
            localStorage.setItem(
              'token',
              response.token
            );


            // Save username
            const loggedInUsername =
              response.user?.username ||
              this.username;

            localStorage.setItem(
              'username',
              loggedInUsername
            );


            this.username =
              loggedInUsername;

            this.isLoggedIn = true;

            this.loginError = '';


            // Load assets
            this.loadAssets();
          }

          else {

            this.loginError =
              response.message ||
              'Login failed.';
          }
        },


        // -----------------------------------------------
        // LOGIN ERROR
        // -----------------------------------------------

        error: (error) => {

          console.error(
            'Login error:',
            error
          );


          if (error.status === 401) {

            this.loginError =
              'Invalid username or password.';
          }

          else if (error.status === 400) {

            this.loginError =
              error.error?.message ||
              'Username and password are required.';
          }

          else if (error.status === 0) {

            this.loginError =
              'Cannot connect to ISMS server. Make sure Flask is running on port 5000.';
          }

          else {

            this.loginError =
              error.error?.message ||
              'Login failed. Please try again.';
          }
        }

      });
  }


  // =====================================================
  // LOAD ASSETS
  // =====================================================

  loadAssets(): void {

    const token =
      localStorage.getItem('token');


    if (!token) {

      this.isLoggedIn = false;

      return;
    }


    this.loadingAssets = true;

    this.assetError = '';


    // JWT Authorization header
    const headers =
      new HttpHeaders({

        'Authorization':
          `Bearer ${token}`
      });


    console.log(
      'Loading assets...'
    );


    this.http
      .get<Asset[]>(
        `${this.apiUrl}/assets`,
        {
          headers: headers
        }
      )
      .subscribe({

        // -----------------------------------------------
        // SUCCESS
        // -----------------------------------------------

        next: (response) => {

          console.log(
            'Assets received:',
            response
          );


          this.assets =
            Array.isArray(response)
              ? response
              : [];


          this.loadingAssets = false;

          this.assetError = '';
        },


        // -----------------------------------------------
        // ERROR
        // -----------------------------------------------

        error: (error) => {

          console.error(
            'Get assets error:',
            error
          );


          this.loadingAssets = false;


          if (error.status === 401) {

            // Token expired/invalid
            localStorage.removeItem(
              'token'
            );

            localStorage.removeItem(
              'username'
            );


            this.isLoggedIn = false;

            this.assets = [];

            this.loginError =
              'Your session has expired. Please login again.';
          }

          else if (error.status === 0) {

            this.assetError =
              'Cannot connect to ISMS server. Make sure Flask is running on http://127.0.0.1:5000.';
          }

          else {

            this.assetError =
              error.error?.message ||
              'Failed to load assets.';
          }
        }

      });
  }


  // =====================================================
  // COUNT WINDOWS ASSETS
  // =====================================================

  getWindowsAssets(): number {

    return this.assets.filter(
      (asset) => {

        const platform =
          asset.platform ||
          asset.operating_system?.Platform ||
          asset.operating_system?.platform ||
          '';

        return String(platform)
          .toLowerCase()
          .includes('windows');
      }
    ).length;
  }


  // =====================================================
  // LOGOUT
  // =====================================================

  logout(): void {

    const token =
      localStorage.getItem('token');


    // Clear frontend session
    localStorage.removeItem(
      'token'
    );

    localStorage.removeItem(
      'username'
    );


    this.isLoggedIn = false;

    this.username = '';

    this.password = '';

    this.assets = [];

    this.loginError = '';

    this.assetError = '';


    // Inform Flask backend
    if (!token) {

      return;
    }


    const headers =
      new HttpHeaders({

        'Authorization':
          `Bearer ${token}`
      });


    this.http
      .post<any>(
        `${this.apiUrl}/logout`,
        {},
        {
          headers: headers
        }
      )
      .subscribe({

        next: (response) => {

          console.log(
            'Logout successful:',
            response
          );
        },

        error: (error) => {

          console.log(
            'Logout request error:',
            error
          );
        }

      });
  }
}