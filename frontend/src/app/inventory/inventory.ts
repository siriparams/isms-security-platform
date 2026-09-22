import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';

import {
  HttpClient,
  HttpClientModule,
  HttpHeaders
} from '@angular/common/http';

import {
  Router,
  RouterLink,
  RouterLinkActive
} from '@angular/router';


interface Asset {

  id: number;

  hostname: string | null;

  ip_address: string | null;

  operating_system?: any;

  hardware?: any;

  network?: any;

  software?: any;

  management?: any;

  security_posture?: any;

  user_context?: any;

  device_identity?: any;

  host_identity?: any;

  discovery_timestamp?: string | null;

  platform?: string | null;

  agent_version?: string | null;

  created_at?: string | null;

  [key: string]: any;
}


@Component({

  selector: 'app-inventory',

  standalone: true,

  imports: [
    CommonModule,
    HttpClientModule,
    RouterLink,
    RouterLinkActive
  ],

  templateUrl: './inventory.html',

  styleUrl: './inventory.css'

})


export class Inventory implements OnInit {


  // =====================================================
  // VARIABLES
  // =====================================================

  username = '';

  private apiUrl =
    'http://127.0.0.1:5000';

  assets: Asset[] = [];

  loading = false;

  error = '';

  totalAssets = 0;

  windowsAssets = 0;

  onlineAssets = 0;

  agentVersion = 'Not collected';


  // =====================================================
  // CONSTRUCTOR
  // =====================================================

  constructor(

    private http: HttpClient,

    private router: Router

  ) {}


  // =====================================================
  // INITIALIZE
  // =====================================================

  ngOnInit(): void {

    this.username =
      localStorage.getItem('username') || 'admin';

    this.loadAssets();

  }


  // =====================================================
  // LOAD ASSETS
  // =====================================================

  loadAssets(): void {

    const token =
      localStorage.getItem('token');


    // -----------------------------------------------------
    // CHECK TOKEN
    // -----------------------------------------------------

    if (!token) {

      this.assets = [];

      this.updateCounts();

      this.loading = false;

      this.error =
        'Authorization token is missing. Please login again.';

      return;

    }


    // -----------------------------------------------------
    // START LOADING
    // -----------------------------------------------------

    this.loading = true;

    this.error = '';


    const headers =
      new HttpHeaders({

        Authorization:
          `Bearer ${token}`

      });


    console.log(
      'Requesting assets from Flask...'
    );


    // -----------------------------------------------------
    // HTTP REQUEST
    // -----------------------------------------------------

    this.http.get<Asset[]>(
      `${this.apiUrl}/assets`,
      {
        headers: headers
      }

    ).subscribe({

      // ===================================================
      // SUCCESS
      // ===================================================

      next: (response: Asset[]) => {

        console.log(
          'Assets received from Flask:',
          response
        );


        // -------------------------------------------------
        // MAKE SURE RESPONSE IS AN ARRAY
        // -------------------------------------------------

        if (Array.isArray(response)) {

          this.assets = response;

        } else {

          this.assets = [];

        }


        // -------------------------------------------------
        // UPDATE COUNTS
        // -------------------------------------------------

        this.updateCounts();


        // -------------------------------------------------
        // STOP LOADING
        // -------------------------------------------------

        this.loading = false;

        this.error = '';


        console.log(
          'Assets displayed:',
          this.assets.length
        );

      },


      // ===================================================
      // ERROR
      // ===================================================

      error: (err: any) => {

        console.error(
          'Asset loading error:',
          err
        );


        this.loading = false;


        // -------------------------------------------------
        // JWT ERROR
        // -------------------------------------------------

        if (err.status === 401) {

          localStorage.removeItem(
            'token'
          );

          localStorage.removeItem(
            'username'
          );

          localStorage.removeItem(
            'selectedAsset'
          );

          this.assets = [];

          this.updateCounts();

          this.error =
            'Your session has expired. Please login again.';

          this.router.navigate([
            '/login'
          ]);

          return;

        }


        // -------------------------------------------------
        // BACKEND NOT RUNNING
        // -------------------------------------------------

        if (err.status === 0) {

          this.error =
            'Cannot connect to ISMS server. Make sure Flask is running on port 5000.';

          return;

        }


        // -------------------------------------------------
        // OTHER ERROR
        // -------------------------------------------------

        this.error =
          err.error?.message ||
          err.error?.error ||
          'Failed to load assets.';

      }

    });

  }


  // =====================================================
  // UPDATE COUNTS
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

        let operatingSystem =
          this.parseJson(
            asset.operating_system
          );


        const platform =
          asset.platform ||
          (
            operatingSystem &&
            typeof operatingSystem === 'object'
              ? (
                  operatingSystem.Platform ||
                  operatingSystem.platform ||
                  operatingSystem.Edition ||
                  operatingSystem.ProductName ||
                  ''
                )
              : operatingSystem || ''
          );


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


        // -----------------------------------------------
        // EXPLICIT ONLINE FIELD
        // -----------------------------------------------

        if (
          asset['online'] === true
        ) {

          return true;

        }


        // -----------------------------------------------
        // STATUS FIELD
        // -----------------------------------------------

        if (
          String(
            asset['status'] || ''
          )
            .toLowerCase() === 'online'
        ) {

          return true;

        }


        // -----------------------------------------------
        // IP ADDRESS
        // -----------------------------------------------

        const ip =
          this.getNetworkIP(asset);


        return (
          ip !== 'N/A' &&
          ip !== 'Not collected' &&
          ip.trim() !== ''
        );

      }

    ).length;

  }


  // =====================================================
  // AGENT VERSION
  // =====================================================

  getAgentVersion(): string {

    for (
      const asset of this.assets
    ) {

      const management =
        this.parseJson(
          asset.management
        );


      const version =
        asset.agent_version ||

        (
          management &&
          typeof management === 'object'
            ? (
                management.Agent_Version ||
                management.agent_version ||
                management.Version ||
                management.version
              )
            : null
        );


      if (
        version !== null &&
        version !== undefined &&
        String(version).trim() !== ''
      ) {

        return String(version);

      }

    }


    return 'Not collected';

  }


  // =====================================================
  // HARDWARE SUMMARY
  // =====================================================

  getHardwareSummary(
    asset: Asset
  ): string {

    const hardware =
      this.parseJson(
        asset.hardware
      );


    if (!hardware) {

      return 'N/A';

    }


    if (
      typeof hardware === 'string'
    ) {

      return hardware;

    }


    const manufacturer =
      hardware.Manufacturer ||
      hardware.manufacturer ||
      '';


    const model =
      hardware.Model ||
      hardware.model ||
      '';


    const cpu =
      hardware.CPU ||
      hardware.cpu ||
      '';


    if (
      manufacturer &&
      model
    ) {

      return `${manufacturer} ${model}`;

    }


    if (model) {

      return String(model);

    }


    if (manufacturer) {

      return String(manufacturer);

    }


    if (cpu) {

      return String(cpu);

    }


    return 'N/A';

  }


  // =====================================================
  // NETWORK SUMMARY
  // =====================================================

  getNetworkSummary(
    asset: Asset
  ): string {

    const network =
      this.parseJson(
        asset.network
      );


    if (!network) {

      return 'N/A';

    }


    if (
      typeof network === 'string'
    ) {

      return network;

    }


    const first =
      Array.isArray(network)
        ? network[0]
        : network;


    if (
      !first ||
      typeof first !== 'object'
    ) {

      return 'N/A';

    }


    return String(

      first.Interface ||

      first.interface ||

      first.Name ||

      first.name ||

      'Network'

    );

  }


  // =====================================================
  // NETWORK IP
  // =====================================================

  getNetworkIP(
    asset: Asset
  ): string {


    // -----------------------------------------------------
    // DIRECT IP ADDRESS
    // -----------------------------------------------------

    const directIP =
      asset.ip_address;


    if (
      directIP &&
      directIP !== 'N/A'
    ) {

      const parsedIP =
        this.parseJson(
          directIP
        );


      if (
        Array.isArray(parsedIP)
      ) {

        return String(
          parsedIP[0] || 'N/A'
        );

      }


      if (
        typeof parsedIP === 'string'
      ) {

        return parsedIP;

      }


      return String(
        directIP
      );

    }


    // -----------------------------------------------------
    // NETWORK OBJECT
    // -----------------------------------------------------

    const network =
      this.parseJson(
        asset.network
      );


    if (!network) {

      return 'N/A';

    }


    const items =
      Array.isArray(network)
        ? network
        : [network];


    // -----------------------------------------------------
    // SEARCH NETWORK INTERFACES
    // -----------------------------------------------------

    for (
      const item of items
    ) {

      if (
        !item ||
        typeof item !== 'object'
      ) {

        continue;

      }


      const ips =
        item.IP_Address ||
        item.ip_address ||
        item.IP ||
        item.ip;


      if (
        Array.isArray(ips)
      ) {

        if (
          ips.length > 0
        ) {

          return String(
            ips[0]
          );

        }

      }


      if (
        ips !== null &&
        ips !== undefined &&
        String(ips).trim() !== ''
      ) {

        return String(
          ips
        );

      }

    }


    return 'N/A';

  }


  // =====================================================
  // OPERATING SYSTEM
  // =====================================================

  getOperatingSystem(
    asset: Asset
  ): string {

    const os =
      this.parseJson(
        asset.operating_system
      );


    if (!os) {

      return asset.platform ||
        'N/A';

    }


    if (
      typeof os === 'string'
    ) {

      return os;

    }


    return String(

      os.Edition ||

      os.ProductName ||

      os.Name ||

      os.name ||

      asset.platform ||

      'N/A'

    );

  }


  // =====================================================
  // PARSE JSON
  // =====================================================

  parseJson(
    data: any
  ): any {

    if (
      data === null ||
      data === undefined
    ) {

      return null;

    }


    // Already an object/array

    if (
      typeof data !== 'string'
    ) {

      return data;

    }


    const trimmed =
      data.trim();


    if (
      trimmed === ''
    ) {

      return null;

    }


    // -----------------------------------------------------
    // TRY TO PARSE JSON
    // -----------------------------------------------------

    try {

      return JSON.parse(
        trimmed
      );

    } catch {

      // If it is ordinary text,
      // return it as it is.

      return data;

    }

  }


  // =====================================================
  // VIEW ASSET
  // =====================================================

  viewAsset(
    asset: Asset
  ): void {

    console.log(
      'Selected asset:',
      asset
    );


    // -----------------------------------------------------
    // SAVE SELECTED ASSET
    // -----------------------------------------------------

    localStorage.setItem(
      'selectedAsset',
      JSON.stringify(asset)
    );


    // -----------------------------------------------------
    // OPEN AUDIT PAGE
    // -----------------------------------------------------

    this.router.navigate([
      '/audit',
      asset.id
    ]);

  }


  // =====================================================
  // FORMAT DATA
  // =====================================================

  formatData(
    data: any
  ): string {

    if (
      data === null ||
      data === undefined ||
      data === ''
    ) {

      return 'N/A';

    }


    if (
      typeof data === 'string'
    ) {

      return data;

    }


    try {

      return JSON.stringify(
        data,
        null,
        2
      );

    } catch {

      return String(
        data
      );

    }

  }


  // =====================================================
  // REFRESH
  // =====================================================

  refresh(): void {

    this.loadAssets();

  }


  // =====================================================
  // LOGOUT
  // =====================================================

  logout(): void {

    localStorage.removeItem(
      'token'
    );

    localStorage.removeItem(
      'username'
    );

    localStorage.removeItem(
      'selectedAsset'
    );


    this.assets = [];

    this.totalAssets = 0;

    this.windowsAssets = 0;

    this.onlineAssets = 0;

    this.agentVersion =
      'Not collected';

    this.loading = false;

    this.error = '';

    this.username = '';


    this.router.navigate([
      '/login'
    ]);

  }

}