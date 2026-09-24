import { Component, OnInit, OnDestroy } from '@angular/core';
import {
  HttpClient,
  HttpClientModule,
  HttpHeaders
} from '@angular/common/http';
import { CommonModule } from '@angular/common';
import { Router, RouterLink } from '@angular/router';

interface Asset {
  id: number;
  hostname?: string | null;
  platform?: string | null;
  agent_version?: string | null;

  online_status?: string | null;
  alert_status?: string | null;

  last_check_in?: string | null;
  heartbeat_interval_seconds?: number | null;
  agent_enabled?: boolean | null;

  operating_system?: any;
}

@Component({
  selector: 'app-home',
  standalone: true,

  imports: [
    CommonModule,
    RouterLink,
    HttpClientModule
  ],

  templateUrl: './home.html',
  styleUrl: './home.css'
})
export class Home implements OnInit, OnDestroy {

  username =
    localStorage.getItem('username') || 'User';

  private apiUrl =
    'http://127.0.0.1:5000';

  assets: Asset[] = [];

  totalAssets = 0;
  windowsAssets = 0;
  onlineAssets = 0;

  agentVersion = '1.0.0';

  error = '';

  private refreshTimer: any;


  constructor(
    private router: Router,
    private http: HttpClient
  ) {}


  ngOnInit(): void {

    this.loadAssets();

    // Refresh every 30 seconds
    this.refreshTimer = setInterval(() => {

      this.loadAssets();

    }, 30000);

  }


  // =====================================================
  // LOAD ASSETS
  // =====================================================

  loadAssets(): void {

    const token =
      localStorage.getItem('token');

    if (!token) {

      this.assets = [];

      this.updateCounts();

      this.error =
        'Authorization token is missing. Please login again.';

      return;

    }


    const headers =
      new HttpHeaders({
        Authorization: `Bearer ${token}`
      });


    this.http.get<Asset[]>(
      `${this.apiUrl}/assets`,
      {
        headers: headers
      }

    ).subscribe({

      next: (response: Asset[]) => {

        this.assets =
          Array.isArray(response)
            ? response
            : [];

        this.updateCounts();

        this.error = '';

      },


      error: (err: any) => {

        console.error(
          'Asset loading error:',
          err
        );


        if (err.status === 401) {

          localStorage.removeItem('token');
          localStorage.removeItem('username');

          this.assets = [];

          this.updateCounts();

          this.error =
            'Your session has expired. Please login again.';

          this.router.navigate(['/login']);

          return;

        }


        if (err.status === 0) {

          this.error =
            'Cannot connect to ISMS server. Make sure Flask is running on port 5000.';

          return;

        }


        this.error =
          err.error?.message ||
          err.error?.error ||
          'Failed to load assets.';

      }

    });

  }


  // =====================================================
  // DASHBOARD COUNTS
  // =====================================================

  updateCounts(): void {

    this.totalAssets =
      this.assets.length;

    this.windowsAssets =
      this.getWindowsAssets();

    this.onlineAssets =
      this.getOnlineAssets();

    this.agentVersion =
      this.getAgentVersion();

  }


  // =====================================================
  // WINDOWS ASSETS
  // =====================================================

  getWindowsAssets(): number {

    return this.assets.filter(
      (asset: Asset) => {

        const platform =
          asset.platform ||
          asset.operating_system?.Platform ||
          asset.operating_system?.platform ||
          asset.operating_system?.Edition ||
          asset.operating_system?.ProductName ||
          '';

        return String(platform)
          .toLowerCase()
          .includes('windows');

      }
    ).length;

  }


  // =====================================================
  // ONLINE ASSETS
  // =====================================================

  getOnlineAssets(): number {

    return this.assets.filter(
      (asset: Asset) => {

        return String(
          asset.online_status || ''
        ).toUpperCase() === 'ONLINE';

      }
    ).length;

  }


  // =====================================================
  // ACTIVE ALERTS
  // =====================================================

  getActiveAlerts(): Asset[] {

    return this.assets.filter(
      (asset: Asset) => {

        const alert =
          String(
            asset.alert_status || 'NONE'
          ).toUpperCase();

        return alert !== 'NONE';

      }
    );

  }


  // =====================================================
  // STATUS TEXT
  // =====================================================

  getAgentStatus(asset: Asset): string {

    const status =
      String(
        asset.online_status || 'UNKNOWN'
      ).toUpperCase();


    if (status === 'ONLINE') {
      return 'ONLINE';
    }


    if (status === 'NOT_RESPONDING') {
      return 'NOT RESPONDING';
    }


    if (status === 'AGENT_DISABLED') {
      return 'AGENT DISABLED';
    }


    return 'UNKNOWN';

  }


  // =====================================================
  // LAST CHECK-IN
  // =====================================================

  getLastCheckIn(asset: Asset): string {

    if (!asset.last_check_in) {

      return 'Never';

    }


    const date =
      new Date(
        asset.last_check_in
      );


    if (
      Number.isNaN(
        date.getTime()
      )
    ) {

      return 'N/A';

    }


    return date.toLocaleString();

  }


  // =====================================================
  // AGENT VERSION
  // =====================================================

  getAgentVersion(): string {

    for (
      const asset of this.assets
    ) {

      if (
        asset.agent_version &&
        String(
          asset.agent_version
        ).trim() !== ''
      ) {

        return String(
          asset.agent_version
        );

      }

    }

    return '1.0.0';

  }


  // =====================================================
  // LOGOUT
  // =====================================================

  logout(): void {

    localStorage.removeItem('token');
    localStorage.removeItem('username');

    this.assets = [];

    this.router.navigate(['/login']);

  }


  // =====================================================
  // CLEANUP
  // =====================================================

  ngOnDestroy(): void {

    if (this.refreshTimer) {

      clearInterval(
        this.refreshTimer
      );

    }

  }

}