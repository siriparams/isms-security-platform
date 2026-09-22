import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import {
  Router,
  RouterLink,
  RouterLinkActive,
  ActivatedRoute
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

interface DisplayField {
  label: string;
  value: string;
}

@Component({
  selector: 'app-audit',
  standalone: true,

  imports: [
    CommonModule,
    RouterLink,
    RouterLinkActive
  ],

  templateUrl: './audit.html',
  styleUrl: './audit.css'
})
export class Audit implements OnInit {

  username =
    localStorage.getItem('username') || 'User';

  asset: Asset | null = null;

  loading = true;

  error = '';

  auditEvaluated = false;

  constructor(
    private route: ActivatedRoute,
    private router: Router
  ) {}

  ngOnInit(): void {
    this.loadSelectedAsset();
  }

  // =====================================================
  // LOAD SELECTED ASSET
  // =====================================================

  loadSelectedAsset(): void {

    this.loading = true;
    this.error = '';

    const storedAsset =
      localStorage.getItem('selectedAsset');

    if (!storedAsset) {

      this.loading = false;

      this.error =
        'No endpoint was selected. Please return to Asset Inventory.';

      return;
    }

    try {

      const selectedAsset: Asset =
        JSON.parse(storedAsset);

      const routeId =
        Number(
          this.route.snapshot.paramMap.get('id')
        );

      if (
        routeId &&
        selectedAsset.id !== routeId
      ) {

        this.loading = false;

        this.error =
          'The selected endpoint could not be found.';

        return;
      }

      this.asset = selectedAsset;

      this.loading = false;

    } catch (error) {

      console.error(
        'Error reading selected asset:',
        error
      );

      this.loading = false;

      this.error =
        'Unable to load endpoint details.';
    }
  }

  // =====================================================
  // BASIC INFORMATION
  // =====================================================

  getHostname(): string {

    return this.asset?.hostname ||
      'Not collected';
  }

  getPlatform(): string {

    return this.asset?.platform ||
      'Not collected';
  }

  getAgentVersion(): string {

    return this.asset?.agent_version ||
      'Not collected';
  }

  // =====================================================
  // IP ADDRESS
  // =====================================================

  getIP(): string {

    if (
      this.asset?.ip_address &&
      this.asset.ip_address !== 'N/A'
    ) {

      return String(
        this.asset.ip_address
      );
    }

    let network =
      this.asset?.network;

    if (!network) {
      return 'Not collected';
    }

    /*
     * PostgreSQL may return the JSON object
     * as a string.
     */
    if (typeof network === 'string') {

      try {

        network =
          JSON.parse(network);

      } catch {

        return 'Not collected';
      }
    }

    if (Array.isArray(network)) {

      for (
        const item of network
      ) {

        if (
          item &&
          typeof item === 'object'
        ) {

          const ip =
            item.IP_Address ||
            item.ip_address ||
            item.IP ||
            item.ip;

          if (Array.isArray(ip)) {

            if (ip.length > 0) {

              return String(
                ip[0]
              );
            }

          } else if (
            ip !== undefined &&
            ip !== null &&
            String(ip).trim() !== ''
          ) {

            return String(ip);
          }
        }
      }
    }

    if (
      typeof network === 'object'
    ) {

      const ip =
        network.IP_Address ||
        network.ip_address ||
        network.IP ||
        network.ip;

      if (Array.isArray(ip)) {

        if (ip.length > 0) {

          return String(
            ip[0]
          );
        }

      } else if (
        ip !== undefined &&
        ip !== null &&
        String(ip).trim() !== ''
      ) {

        return String(ip);
      }
    }

    return 'Not collected';
  }

  // =====================================================
  // OPERATING SYSTEM
  // =====================================================

  getOSFields(): DisplayField[] {

    let os =
      this.asset?.operating_system;

    if (!os) {
      return [];
    }

    /*
     * PostgreSQL may return JSON as a string.
     */
    if (typeof os === 'string') {

      try {

        os =
          JSON.parse(os);

      } catch {

        return [
          {
            label: 'Operating System',
            value: os
          }
        ];
      }
    }

    if (
      typeof os === 'object' &&
      !Array.isArray(os)
    ) {

      return this.objectToFields(os);
    }

    return [
      {
        label: 'Operating System',
        value: this.formatValue(os)
      }
    ];
  }

  // =====================================================
  // HARDWARE
  // =====================================================

  getHardwareFields(): DisplayField[] {

    let hardware =
      this.asset?.hardware;

    if (!hardware) {
      return [];
    }

    if (typeof hardware === 'string') {

      try {

        hardware =
          JSON.parse(hardware);

      } catch {

        return [
          {
            label: 'Hardware',
            value: hardware
          }
        ];
      }
    }

    if (
      typeof hardware === 'object' &&
      !Array.isArray(hardware)
    ) {

      return this.objectToFields(
        hardware
      );
    }

    return [
      {
        label: 'Hardware',
        value: this.formatValue(
          hardware
        )
      }
    ];
  }

  // =====================================================
  // NETWORK
  // =====================================================

  getNetworkFields(): DisplayField[] {

    let network =
      this.asset?.network;

    if (!network) {
      return [];
    }

    /*
     * Convert JSON string into
     * an actual object/array.
     */
    if (typeof network === 'string') {

      try {

        network =
          JSON.parse(network);

      } catch {

        return [
          {
            label: 'Network',
            value: network
          }
        ];
      }
    }

    /*
     * The Windows agent stores
     * network information as an array.
     */
    if (Array.isArray(network)) {

      if (network.length === 0) {
        return [];
      }

      const item =
        network[0];

      if (
        !item ||
        typeof item !== 'object'
      ) {
        return [];
      }

      return Object.keys(item)
        .map(key => {

          return {
            label:
              this.formatLabel(key),

            value:
              this.formatValue(
                item[key]
              )
          };

        });
    }

    if (
      typeof network === 'object'
    ) {

      return Object.keys(network)
        .map(key => {

          return {
            label:
              this.formatLabel(key),

            value:
              this.formatValue(
                network[key]
              )
          };

        });
    }

    return [];
  }

  // =====================================================
  // SECURITY POSTURE
  // =====================================================

  getSecurityFields(): DisplayField[] {

    return this.getObjectFields(
      this.asset?.security_posture
    );
  }

  // =====================================================
  // MANAGEMENT
  // =====================================================

  getManagementFields(): DisplayField[] {

    return this.getObjectFields(
      this.asset?.management
    );
  }

  // =====================================================
  // USER CONTEXT
  // =====================================================

  getUserContextFields(): DisplayField[] {

    return this.getObjectFields(
      this.asset?.user_context
    );
  }

  // =====================================================
  // SOFTWARE
  // =====================================================

  getSoftwareFields(): DisplayField[] {

    const software =
      this.parseJSON(
        this.asset?.software
      );

    if (!software) {
      return [];
    }

    /*
     * Software is normally an array.
     * We return a summary here so the
     * page doesn't become one huge JSON block.
     */
    if (Array.isArray(software)) {

      return software.map(
        (item: any, index: number) => {

          if (
            item &&
            typeof item === 'object'
          ) {

            const name =
              item.Name ||
              item.name ||
              'Unknown software';

            const version =
              item.Version ||
              item.version ||
              'Version not collected';

            const publisher =
              item.Publisher ||
              item.publisher ||
              'Publisher not collected';

            return {
              label: `${index + 1}. ${name}`,
              value:
                `Version: ${version} | Publisher: ${publisher}`
            };
          }

          return {
            label: `${index + 1}`,
            value: String(item)
          };
        }
      );
    }

    return this.getObjectFields(
      software
    );
  }

  // =====================================================
  // DEVICE IDENTITY
  // =====================================================

  getDeviceIdentityFields(): DisplayField[] {

    return this.getObjectFields(
      this.asset?.device_identity
    );
  }

  // =====================================================
  // HOST IDENTITY
  // =====================================================

  getHostIdentityFields(): DisplayField[] {

    return this.getObjectFields(
      this.asset?.host_identity
    );
  }

  // =====================================================
  // GENERIC OBJECT HANDLING
  // =====================================================

  getObjectFields(
    data: any
  ): DisplayField[] {

    const parsed =
      this.parseJSON(data);

    if (
      parsed === null ||
      parsed === undefined ||
      parsed === ''
    ) {

      return [];
    }

    if (
      typeof parsed === 'string'
    ) {

      return [
        {
          label: 'Information',
          value: parsed
        }
      ];
    }

    if (Array.isArray(parsed)) {

      if (parsed.length === 0) {
        return [];
      }

      /*
       * If this is an array of objects,
       * display each object in a readable way.
       */
      return parsed.map(
        (item: any, index: number) => {

          if (
            item &&
            typeof item === 'object'
          ) {

            const readable =
              Object.keys(item)
                .map(key =>
                  `${this.formatLabel(key)}: ${this.formatValue(item[key])}`
                )
                .join(' | ');

            return {
              label: `Item ${index + 1}`,
              value: readable
            };
          }

          return {
            label: `Item ${index + 1}`,
            value: String(item)
          };
        }
      );
    }

    if (
      typeof parsed === 'object'
    ) {

      return this.objectToFields(
        parsed
      );
    }

    return [
      {
        label: 'Information',
        value: String(parsed)
      }
    ];
  }

  // =====================================================
  // CONVERT JSON STRING → OBJECT
  // =====================================================

  parseJSON(
    value: any
  ): any {

    if (
      value === null ||
      value === undefined
    ) {
      return null;
    }

    if (
      typeof value !== 'string'
    ) {
      return value;
    }

    const trimmed =
      value.trim();

    if (
      trimmed === ''
    ) {
      return '';
    }

    /*
     * Only attempt JSON parsing when
     * the string looks like JSON.
     */
    if (
      (
        trimmed.startsWith('{') &&
        trimmed.endsWith('}')
      ) ||
      (
        trimmed.startsWith('[') &&
        trimmed.endsWith(']')
      )
    ) {

      try {

        return JSON.parse(
          trimmed
        );

      } catch {

        return value;
      }
    }

    return value;
  }

  // =====================================================
  // OBJECT → DISPLAY FIELDS
  // =====================================================

  objectToFields(
    data: any
  ): DisplayField[] {

    if (
      !data ||
      typeof data !== 'object' ||
      Array.isArray(data)
    ) {

      return [];
    }

    return Object.keys(data)
      .map(key => {

        return {
          label:
            this.formatLabel(key),

          value:
            this.formatValue(
              data[key]
            )
        };

      });
  }

  // =====================================================
  // FORMAT FIELD LABEL
  // =====================================================

  formatLabel(
    key: string
  ): string {

    return key
      .replace(/_/g, ' ')
      .replace(/-/g, ' ')
      .replace(
        /\w\S*/g,
        word =>
          word.charAt(0).toUpperCase() +
          word.slice(1).toLowerCase()
      );
  }

  // =====================================================
  // FORMAT VALUES
  // =====================================================

  formatValue(
    value: any
  ): string {

    if (
      value === null ||
      value === undefined ||
      value === ''
    ) {

      return 'Not collected';
    }

    /*
     * If PostgreSQL returned nested
     * JSON as a string, parse it.
     */
    if (
      typeof value === 'string'
    ) {

      const parsed =
        this.parseJSON(value);

      if (
        parsed !== value
      ) {

        return this.formatValue(
          parsed
        );
      }

      return value;
    }

    if (
      typeof value === 'boolean'
    ) {

      return value
        ? 'Yes'
        : 'No';
    }

    if (
      Array.isArray(value)
    ) {

      if (value.length === 0) {
        return 'Not collected';
      }

      return value
        .map(item => {

          if (
            item &&
            typeof item === 'object'
          ) {

            return Object.keys(item)
              .map(key =>
                `${this.formatLabel(key)}: ${this.formatValue(item[key])}`
              )
              .join(' | ');
          }

          return String(item);

        })
        .join(', ');
    }

    if (
      typeof value === 'object'
    ) {

      return Object.keys(value)
        .map(key =>
          `${this.formatLabel(key)}: ${this.formatValue(value[key])}`
        )
        .join(' | ');
    }

    return String(value);
  }

  // =====================================================
  // AUDIT STATUS
  // =====================================================

  getAuditStatus(): string {

    if (this.auditEvaluated) {

      return 'Audit evaluated';
    }

    return 'Not evaluated';
  }

  getAuditDescription(): string {

    if (this.auditEvaluated) {

      return 'Results are based on the endpoint audit evidence.';
    }

    return 'The security checklist has not yet been evaluated for this endpoint.';
  }

  // =====================================================
  // RUN AUDIT
  // =====================================================

  runAudit(): void {

    alert(
      'The Windows audit engine is being prepared. No audit result has been generated yet.'
    );
  }

  // =====================================================
  // EXPORT REPORT
  // =====================================================

  exportReport(): void {

    if (!this.asset) {
      return;
    }

    const report = {

      report_type:
        'Endpoint Audit Details',

      generated_at:
        new Date().toISOString(),

      endpoint:
        this.asset,

      audit_status:
        this.getAuditStatus()
    };

    const blob =
      new Blob(
        [
          JSON.stringify(
            report,
            null,
            2
          )
        ],
        {
          type:
            'application/json'
        }
      );

    const url =
      window.URL.createObjectURL(
        blob
      );

    const link =
      document.createElement('a');

    link.href =
      url;

    link.download =
      `${this.asset.hostname || 'endpoint'}-audit-report.json`;

    link.click();

    window.URL.revokeObjectURL(
      url
    );
  }

  // =====================================================
  // NAVIGATION
  // =====================================================

  backToInventory(): void {

    this.router.navigate([
      '/inventory'
    ]);
  }

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

    this.router.navigate([
      '/login'
    ]);
  }
}