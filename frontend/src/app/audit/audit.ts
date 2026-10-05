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

interface AuditCheck {
  id: number;
  audit_id: string;
  check_id: string;
  check_name: string;
  category: string;
  expected_value: string;
  observed_value: string;
  status: string;
  severity: string;
  evidence: string;
}

interface AuditResult {
  audit_id: string;
  asset_id: number;
  hostname: string;
  operating_system: string;
  os_version: string;
  audit_profile: string;
  compliance_standard: string;
  audit_timestamp: string;

  overall_score: number;
  passed_count: number;
  failed_count: number;
  total_checks: number;
  status: string;

  checks: AuditCheck[];
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

  auditResult: AuditResult | null = null;

  auditLoading = false;

  auditError = '';

  constructor(
    private route: ActivatedRoute,
    private router: Router
  ) {}

  // =====================================================
  // INITIALIZE
  // =====================================================

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

      /*
       * Automatically run the audit once the
       * endpoint information has loaded.
       */
      this.runAudit();

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
  // RUN AUDIT
  // =====================================================

  runAudit(): void {

    if (!this.asset) {
      return;
    }

    const asset = this.asset;

    this.auditLoading = true;
    this.auditError = '';

    /*
     * Small delay so the UI visibly shows
     * "Running Audit..." before displaying
     * the result.
     */
    setTimeout(() => {

      try {

        const checks =
          this.buildAuditChecks();

        const passed =
          checks.filter(
            check =>
              check.status === 'PASS'
          ).length;

        const failed =
          checks.filter(
            check =>
              check.status === 'FAIL'
          ).length;

        const manual =
          checks.filter(
            check =>
              check.status === 'MANUAL REVIEW'
          ).length;

        const evaluated =
          passed + failed;

        const score =
          evaluated > 0
            ? Math.round(
                (passed / evaluated) * 100
              )
            : 0;

        const auditId =
          this.generateAuditId();

        const result: AuditResult = {

          audit_id: auditId,

          asset_id:
            asset.id,

          hostname:
            asset.hostname ||
            'Unknown',

          operating_system:
            this.getOSName(),

          os_version:
            this.getOSVersion(),

          audit_profile:
            'Windows Endpoint Security Audit',

          compliance_standard:
            'ISMS Security Baseline',

          audit_timestamp:
            new Date().toISOString(),

          overall_score:
            score,

          passed_count:
            passed,

          failed_count:
            failed,

          total_checks:
            checks.length,

          status:
            failed === 0
              ? 'PASSED'
              : 'FAILED',

          checks:
            checks
        };

        this.auditResult =
          result;

        this.auditLoading =
          false;

        this.auditError = '';

        /*
         * Keep latest result available even
         * after page refresh.
         */
        localStorage.setItem(
          `auditResult_${asset.id}`,
          JSON.stringify(result)
        );

        console.log(
          'Audit completed:',
          result
        );

      } catch (error) {

        console.error(
          'Audit generation error:',
          error
        );

        this.auditLoading =
          false;

        this.auditResult =
          null;

        this.auditError =
          'Unable to generate the endpoint audit.';
      }

    }, 500);
  }

  // =====================================================
  // BUILD 40 SECURITY CHECKS
  // =====================================================

  buildAuditChecks(): AuditCheck[] {

    if (!this.asset) {
      return [];
    }

    const checks: AuditCheck[] = [];

    const security =
      this.parseJSON(
        this.asset.security_posture
      ) || {};

    const management =
      this.parseJSON(
        this.asset.management
      ) || {};

    const deviceIdentity =
      this.parseJSON(
        this.asset.device_identity
      ) || {};

    const hostIdentity =
      this.parseJSON(
        this.asset.host_identity
      ) || {};

    const hardware =
      this.parseJSON(
        this.asset.hardware
      ) || {};

    const network =
      this.parseJSON(
        this.asset.network
      );

    const os =
      this.parseJSON(
        this.asset.operating_system
      ) || {};

    const software =
      this.parseJSON(
        this.asset.software
      );

    // ===================================================
    // HELPER
    // ===================================================

    const addCheck = (
      id: number,
      name: string,
      category: string,
      expected: string,
      observed: string,
      status: string,
      severity: string,
      evidence: string
    ) => {

      checks.push({

        id,

        audit_id: '',

        check_id:
          `WIN-${String(id).padStart(3, '0')}`,

        check_name:
          name,

        category,

        expected_value:
          expected,

        observed_value:
          observed,

        status,

        severity,

        evidence
      });
    };

    // ===================================================
    // 1-10 : NETWORK & ENDPOINT SECURITY
    // ===================================================

    const firewallValue =
      this.findValue(
        security,
        [
          'Firewall',
          'firewall',
          'Firewall_Status',
          'firewall_status'
        ]
      );

    addCheck(
      1,
      'Windows Firewall Enabled',
      'Network Security',
      'Enabled',
      this.cleanValue(firewallValue),
      this.isEnabledValue(firewallValue)
        ? 'PASS'
        : this.isMissing(firewallValue)
          ? 'MANUAL REVIEW'
          : 'FAIL',
      'HIGH',
      'Windows Firewall status collected by endpoint agent.'
    );

    const antivirus =
      this.findValue(
        security,
        [
          'Antivirus_EDR',
          'antivirus_edr',
          'Antivirus',
          'antivirus'
        ]
      );

    addCheck(
      2,
      'Antivirus / EDR Present',
      'Endpoint Protection',
      'Present and enabled',
      this.cleanValue(antivirus),
      this.hasSecurityProduct(antivirus)
        ? 'PASS'
        : this.isMissing(antivirus)
          ? 'MANUAL REVIEW'
          : 'FAIL',
      'HIGH',
      'Endpoint antivirus / EDR information collected.'
    );

    const edr =
      this.findValue(
        security,
        [
          'EDR_Present',
          'edr_present',
          'EDR',
          'edr'
        ]
      );

    addCheck(
      3,
      'EDR Protection Present',
      'Endpoint Protection',
      'Yes',
      this.cleanValue(edr),
      this.isYes(edr)
        ? 'PASS'
        : this.isMissing(edr)
          ? 'MANUAL REVIEW'
          : 'FAIL',
      'HIGH',
      'EDR presence reported by endpoint agent.'
    );

    const updateStatus =
      this.findValue(
        security,
        [
          'Update_Status',
          'update_status',
          'Windows_Update',
          'windows_update'
        ]
      );

    addCheck(
      4,
      'Windows Update Status',
      'Patch Management',
      'Updates current',
      this.cleanValue(updateStatus),
      this.isUpdateCurrent(updateStatus)
        ? 'PASS'
        : this.isMissing(updateStatus)
          ? 'MANUAL REVIEW'
          : 'FAIL',
      'HIGH',
      'Windows Update information collected by endpoint agent.'
    );

    const secureBoot =
      this.findValue(
        os,
        [
          'Secure_Boot',
          'secure_boot',
          'SecureBoot',
          'secureboot'
        ]
      ) ||
      this.findValue(
        security,
        [
          'Secure_Boot',
          'secure_boot'
        ]
      );

    addCheck(
      5,
      'Secure Boot Enabled',
      'System Security',
      'Enabled',
      this.cleanValue(secureBoot),
      this.isYes(secureBoot)
        ? 'PASS'
        : this.isMissing(secureBoot)
          ? 'MANUAL REVIEW'
          : 'FAIL',
      'MEDIUM',
      'Secure Boot state collected from endpoint.'
    );

    const encryption =
      this.findValue(
        security,
        [
          'Encryption',
          'encryption',
          'BitLocker',
          'bitlocker'
        ]
      );

    addCheck(
      6,
      'Disk Encryption',
      'Data Protection',
      'Encrypted',
      this.cleanValue(encryption),
      this.isEncrypted(encryption)
        ? 'PASS'
        : this.isMissing(encryption)
          ? 'MANUAL REVIEW'
          : 'FAIL',
      'HIGH',
      'BitLocker / encryption information collected by endpoint agent.'
    );

    addCheck(
      7,
      'Device Identity Available',
      'Asset Management',
      'Machine GUID and SMBIOS UUID available',
      this.getIdentityValue(
        deviceIdentity
      ),
      this.hasDeviceIdentity(
        deviceIdentity
      )
        ? 'PASS'
        : 'FAIL',
      'HIGH',
      'Unique endpoint identity information.'
    );

    addCheck(
      8,
      'Hostname Available',
      'Asset Management',
      'Hostname collected',
      this.asset.hostname ||
        'Not collected',
      this.asset.hostname
        ? 'PASS'
        : 'FAIL',
      'MEDIUM',
      'Endpoint hostname collected during discovery.'
    );

    addCheck(
      9,
      'IP Address Available',
      'Network Security',
      'IP address collected',
      this.getIP(),
      this.getIP() !== 'Not collected'
        ? 'PASS'
        : 'MANUAL REVIEW',
      'MEDIUM',
      'Network address information collected from endpoint.'
    );

    addCheck(
      10,
      'Network Interface Available',
      'Network Security',
      'Network interface collected',
      this.getNetworkInterface(network),
      this.hasNetwork(network)
        ? 'PASS'
        : 'MANUAL REVIEW',
      'LOW',
      'Network interface information collected.'
    );

    // ===================================================
    // 11-20 : SYSTEM & HARDENING
    // ===================================================

    addCheck(
      11,
      'Operating System Identified',
      'System Security',
      'Operating system identified',
      this.getOSName(),
      this.getOSName() !== 'Not collected'
        ? 'PASS'
        : 'FAIL',
      'MEDIUM',
      'Operating system information collected.'
    );

    addCheck(
      12,
      'OS Version Available',
      'System Security',
      'OS version collected',
      this.getOSVersion(),
      this.getOSVersion() !== 'Not collected'
        ? 'PASS'
        : 'MANUAL REVIEW',
      'LOW',
      'OS version information collected.'
    );

    const build =
      this.findValue(
        os,
        [
          'Build',
          'build',
          'OS_Build',
          'os_build'
        ]
      );

    addCheck(
      13,
      'OS Build Available',
      'System Security',
      'Build number collected',
      this.cleanValue(build),
      this.isMissing(build)
        ? 'MANUAL REVIEW'
        : 'PASS',
      'LOW',
      'Operating system build information.'
    );

    const lastBoot =
      this.findValue(
        os,
        [
          'Last_Boot',
          'last_boot',
          'LastBoot',
          'lastboot'
        ]
      );

    addCheck(
      14,
      'Last Boot Information',
      'System Monitoring',
      'Last boot time collected',
      this.cleanValue(lastBoot),
      this.isMissing(lastBoot)
        ? 'MANUAL REVIEW'
        : 'PASS',
      'LOW',
      'Last boot timestamp collected.'
    );

    const manufacturer =
      this.findValue(
        hardware,
        [
          'Manufacturer',
          'manufacturer'
        ]
      );

    addCheck(
      15,
      'Hardware Manufacturer Identified',
      'Asset Management',
      'Manufacturer collected',
      this.cleanValue(manufacturer),
      this.isMissing(manufacturer)
        ? 'MANUAL REVIEW'
        : 'PASS',
      'LOW',
      'Hardware manufacturer information.'
    );

    const model =
      this.findValue(
        hardware,
        [
          'Model',
          'model'
        ]
      );

    addCheck(
      16,
      'Hardware Model Identified',
      'Asset Management',
      'Model collected',
      this.cleanValue(model),
      this.isMissing(model)
        ? 'MANUAL REVIEW'
        : 'PASS',
      'LOW',
      'Hardware model information.'
    );

    const serial =
      this.findValue(
        hardware,
        [
          'Serial_Number',
          'serial_number',
          'SerialNumber',
          'serialnumber'
        ]
      );

    addCheck(
      17,
      'Hardware Serial Number',
      'Asset Management',
      'Serial number collected',
      this.cleanValue(serial),
      this.isMissing(serial)
        ? 'MANUAL REVIEW'
        : 'PASS',
      'LOW',
      'Hardware serial number.'
    );

    const cpu =
      this.findValue(
        hardware,
        [
          'CPU',
          'cpu',
          'Processor',
          'processor'
        ]
      );

    addCheck(
      18,
      'CPU Information',
      'Asset Management',
      'CPU information collected',
      this.cleanValue(cpu),
      this.isMissing(cpu)
        ? 'MANUAL REVIEW'
        : 'PASS',
      'LOW',
      'CPU information collected.'
    );

    const ram =
      this.findValue(
        hardware,
        [
          'RAM_GB',
          'ram_gb',
          'RAM',
          'ram',
          'Memory'
        ]
      );

    addCheck(
      19,
      'Memory Information',
      'Asset Management',
      'Memory information collected',
      this.cleanValue(ram),
      this.isMissing(ram)
        ? 'MANUAL REVIEW'
        : 'PASS',
      'LOW',
      'System memory information.'
    );

    const disks =
      this.findValue(
        hardware,
        [
          'Disks',
          'disks',
          'Disk',
          'disk'
        ]
      );

    addCheck(
      20,
      'Disk Inventory Available',
      'Asset Management',
      'Disk information collected',
      this.cleanValue(disks),
      this.isMissing(disks)
        ? 'MANUAL REVIEW'
        : 'PASS',
      'LOW',
      'Storage device information collected.'
    );

    // ===================================================
    // 21-30 : IDENTITY / MANAGEMENT / NETWORK
    // ===================================================

    const fqdn =
      this.findValue(
        hostIdentity,
        [
          'FQDN',
          'fqdn'
        ]
      );

    addCheck(
      21,
      'FQDN Available',
      'Host Identity',
      'FQDN collected',
      this.cleanValue(fqdn),
      this.isMissing(fqdn)
        ? 'MANUAL REVIEW'
        : 'PASS',
      'LOW',
      'Fully qualified domain name information.'
    );

    const domain =
      this.findValue(
        hostIdentity,
        [
          'Domain',
          'domain'
        ]
      );

    addCheck(
      22,
      'Domain Information',
      'Host Identity',
      'Domain information collected',
      this.cleanValue(domain),
      this.isMissing(domain)
        ? 'MANUAL REVIEW'
        : 'PASS',
      'LOW',
      'Windows domain/workgroup information.'
    );

    const domainJoined =
      this.findValue(
        hostIdentity,
        [
          'Domain_Joined',
          'domain_joined',
          'DomainJoined',
          'domainjoined'
        ]
      );

    addCheck(
      23,
      'Domain Join Status',
      'Identity Management',
      'Domain join status known',
      this.cleanValue(domainJoined),
      this.isMissing(domainJoined)
        ? 'MANUAL REVIEW'
        : 'PASS',
      'MEDIUM',
      'Domain join state collected.'
    );

    const localDevice =
      this.findValue(
        hostIdentity,
        [
          'Local_Device_Name',
          'local_device_name',
          'LocalDeviceName'
        ]
      );

    addCheck(
      24,
      'Local Device Name',
      'Host Identity',
      'Device name collected',
      this.cleanValue(localDevice),
      this.isMissing(localDevice)
        ? 'MANUAL REVIEW'
        : 'PASS',
      'LOW',
      'Local device name collected.'
    );

    const agentVersion =
      this.asset.agent_version;

    addCheck(
      25,
      'Agent Version Available',
      'Agent Management',
      'Agent version identified',
      agentVersion ||
        'Not collected',
      agentVersion
        ? 'PASS'
        : 'FAIL',
      'MEDIUM',
      'ISMS endpoint agent version.'
    );

    const lastCheckIn =
      this.findValue(
        management,
        [
          'Last_Check_In',
          'last_check_in',
          'LastCheckIn'
        ]
      );

    addCheck(
      26,
      'Agent Check-In Information',
      'Agent Management',
      'Last check-in available',
      this.cleanValue(lastCheckIn),
      this.isMissing(lastCheckIn)
        ? 'MANUAL REVIEW'
        : 'PASS',
      'MEDIUM',
      'Agent management information.'
    );

    const mdm =
      this.findValue(
        management,
        [
          'MDM_Intune',
          'mdm_intune',
          'MDM',
          'Intune'
        ]
      );

    addCheck(
      27,
      'MDM / Intune Information',
      'Device Management',
      'Management state collected',
      this.cleanValue(mdm),
      this.isMissing(mdm)
        ? 'MANUAL REVIEW'
        : 'PASS',
      'LOW',
      'MDM / Intune information collected.'
    );

    const gateway =
      this.findNetworkValue(
        network,
        [
          'Gateway',
          'gateway',
          'Default_Gateway',
          'default_gateway'
        ]
      );

    addCheck(
      28,
      'Default Gateway Information',
      'Network Security',
      'Gateway collected',
      this.cleanValue(gateway),
      this.isMissing(gateway)
        ? 'MANUAL REVIEW'
        : 'PASS',
      'LOW',
      'Default gateway information.'
    );

    const dns =
      this.findNetworkValue(
        network,
        [
          'DNS',
          'dns',
          'Dns',
          'DNS_Servers'
        ]
      );

    addCheck(
      29,
      'DNS Information',
      'Network Security',
      'DNS information collected',
      this.cleanValue(dns),
      this.isMissing(dns)
        ? 'MANUAL REVIEW'
        : 'PASS',
      'LOW',
      'DNS configuration information.'
    );

    addCheck(
      30,
      'MAC Address Available',
      'Network Security',
      'MAC address collected',
      this.getMACAddress(network),
      this.getMACAddress(network) !== 'Not collected'
        ? 'PASS'
        : 'MANUAL REVIEW',
      'MEDIUM',
      'Network adapter MAC address.'
    );

    // ===================================================
    // 31-40 : SECURITY / INVENTORY
    // ===================================================

    const localAdmins =
      this.findValue(
        security,
        [
          'Local_Administrators',
          'local_administrators',
          'LocalAdministrators',
          'local_admins'
        ]
      );

    addCheck(
      31,
      'Local Administrator Inventory',
      'Privilege Management',
      'Local administrators collected',
      this.cleanValue(localAdmins),
      this.isMissing(localAdmins)
        ? 'MANUAL REVIEW'
        : 'PASS',
      'MEDIUM',
      'Local administrator information collected.'
    );

    addCheck(
      32,
      'TPM Presence',
      'Hardware Security',
      'TPM state collected',
      this.getTPMValue(deviceIdentity),
      this.hasTPMInfo(deviceIdentity)
        ? 'PASS'
        : 'MANUAL REVIEW',
      'MEDIUM',
      'TPM information collected by endpoint agent.'
    );

    const tpmVersion =
      this.findValue(
        deviceIdentity,
        [
          'TPM_Spec_Version',
          'tpm_spec_version',
          'TPM_SpecVersion'
        ]
      );

    addCheck(
      33,
      'TPM Specification Version',
      'Hardware Security',
      'TPM specification collected',
      this.cleanValue(tpmVersion),
      this.isMissing(tpmVersion)
        ? 'MANUAL REVIEW'
        : 'PASS',
      'LOW',
      'TPM specification information.'
    );

    const loggedUser =
      this.findValue(
        this.parseJSON(
          this.asset.user_context
        ) || {},
        [
          'Current_User',
          'current_user',
          'Username',
          'username'
        ]
      );

    addCheck(
      34,
      'Current User Information',
      'User Security',
      'Current user identified',
      this.cleanValue(loggedUser),
      this.isMissing(loggedUser)
        ? 'MANUAL REVIEW'
        : 'PASS',
      'LOW',
      'Current user information collected.'
    );

    const lastUser =
      this.findValue(
        this.parseJSON(
          this.asset.user_context
        ) || {},
        [
          'Last_Logged_User',
          'last_logged_user',
          'LastLoggedUser'
        ]
      );

    addCheck(
      35,
      'Last Logged User',
      'User Security',
      'Last logged user collected',
      this.cleanValue(lastUser),
      this.isMissing(lastUser)
        ? 'MANUAL REVIEW'
        : 'PASS',
      'LOW',
      'Last logged user information.'
    );

    addCheck(
      36,
      'Software Inventory',
      'Software Management',
      'Software inventory collected',
      this.getSoftwareCount(software),
      this.hasSoftware(software)
        ? 'PASS'
        : 'MANUAL REVIEW',
      'MEDIUM',
      'Installed software inventory collected.'
    );

    addCheck(
      37,
      'Device Manufacturer',
      'Asset Management',
      'Manufacturer identified',
      this.cleanValue(manufacturer),
      this.isMissing(manufacturer)
        ? 'MANUAL REVIEW'
        : 'PASS',
      'LOW',
      'Device manufacturer information.'
    );

    addCheck(
      38,
      'Device Model',
      'Asset Management',
      'Model identified',
      this.cleanValue(model),
      this.isMissing(model)
        ? 'MANUAL REVIEW'
        : 'PASS',
      'LOW',
      'Device model information.'
    );

    addCheck(
      39,
      'Asset Discovery Timestamp',
      'Asset Management',
      'Discovery timestamp available',
      this.asset.discovery_timestamp ||
        'Not collected',
      this.asset.discovery_timestamp
        ? 'PASS'
        : 'MANUAL REVIEW',
      'LOW',
      'Timestamp from endpoint discovery.'
    );

    addCheck(
      40,
      'ISMS Asset Record',
      'Asset Management',
      'Asset exists in ISMS inventory',
      `Asset ID ${this.asset.id}`,
      this.asset.id
        ? 'PASS'
        : 'FAIL',
      'HIGH',
      'Endpoint exists in the ISMS asset inventory.'
    );

    return checks;
  }

  // =====================================================
  // GET HOSTNAME
  // =====================================================

  getHostname(): string {

    return this.asset?.hostname ||
      'Not collected';
  }

  // =====================================================
  // GET PLATFORM
  // =====================================================

  getPlatform(): string {

    return this.asset?.platform ||
      'Not collected';
  }

  // =====================================================
  // GET AGENT VERSION
  // =====================================================

  getAgentVersion(): string {

    return this.asset?.agent_version ||
      'Not collected';
  }

  // =====================================================
  // GET IP
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

    const network =
      this.parseJSON(
        this.asset?.network
      );

    const value =
      this.findNetworkValue(
        network,
        [
          'IP_Address',
          'ip_address',
          'IP',
          'ip'
        ]
      );

    if (!this.isMissing(value)) {

      return String(value);
    }

    return 'Not collected';
  }

  // =====================================================
  // OS
  // =====================================================

  getOSFields(): DisplayField[] {

    const os =
      this.parseJSON(
        this.asset?.operating_system
      );

    return this.objectToFields(os);
  }

  getOSName(): string {

    const os =
      this.parseJSON(
        this.asset?.operating_system
      ) || {};

    const value =
      this.findValue(
        os,
        [
          'Edition',
          'edition',
          'Name',
          'name',
          'Operating_System',
          'operating_system'
        ]
      );

    if (!this.isMissing(value)) {
      return String(value);
    }

    return 'Not collected';
  }

  getOSVersion(): string {

    const os =
      this.parseJSON(
        this.asset?.operating_system
      ) || {};

    const value =
      this.findValue(
        os,
        [
          'Version',
          'version',
          'OS_Version',
          'os_version'
        ]
      );

    if (!this.isMissing(value)) {
      return String(value);
    }

    return 'Not collected';
  }

  // =====================================================
  // HARDWARE
  // =====================================================

  getHardwareFields(): DisplayField[] {

    const hardware =
      this.parseJSON(
        this.asset?.hardware
      );

    return this.objectToFields(
      hardware
    );
  }

  // =====================================================
  // NETWORK
  // =====================================================

  getNetworkFields(): DisplayField[] {

    const network =
      this.parseJSON(
        this.asset?.network
      );

    if (Array.isArray(network)) {

      const result: DisplayField[] = [];

      network.forEach(
        (item: any) => {

          if (
            item &&
            typeof item === 'object'
          ) {

            Object.keys(item)
              .forEach(
                key => {

                  result.push({

                    label:
                      this.formatLabel(
                        key
                      ),

                    value:
                      this.formatValue(
                        item[key]
                      )

                  });

                }
              );
          }

        }
      );

      return result;
    }

    return this.objectToFields(
      network
    );
  }

  // =====================================================
  // SECURITY
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

    if (Array.isArray(software)) {

      return software.map(
        (
          item: any,
          index: number
        ) => {

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

              label:
                `${index + 1}. ${name}`,

              value:
                `Version: ${version} | Publisher: ${publisher}`
            };
          }

          return {

            label:
              `${index + 1}`,

            value:
              String(item)
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
  // OBJECT FIELDS
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
          label:
            'Information',

          value:
            parsed
        }

      ];
    }

    if (Array.isArray(parsed)) {

      return parsed.map(
        (
          item: any,
          index: number
        ) => {

          if (
            item &&
            typeof item === 'object'
          ) {

            return {

              label:
                `Item ${index + 1}`,

              value:
                Object.keys(item)
                  .map(
                    key =>
                      `${this.formatLabel(key)}: ${this.formatValue(item[key])}`
                  )
                  .join(' | ')
            };
          }

          return {

            label:
              `Item ${index + 1}`,

            value:
              String(item)
          };

        }
      );
    }

    return this.objectToFields(
      parsed
    );
  }

  // =====================================================
  // OBJECT TO FIELDS
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
      .map(
        key => ({

          label:
            this.formatLabel(key),

          value:
            this.formatValue(
              data[key]
            )

        })
      );
  }

  // =====================================================
  // JSON PARSER
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
  // FORMAT VALUE
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

    if (Array.isArray(value)) {

      if (value.length === 0) {

        return 'Not collected';
      }

      return value
        .map(
          item => {

            if (
              item &&
              typeof item === 'object'
            ) {

              return Object.keys(item)
                .map(
                  key =>
                    `${this.formatLabel(key)}: ${this.formatValue(item[key])}`
                )
                .join(' | ');
            }

            return String(item);

          }
        )
        .join(', ');
    }

    if (
      typeof value === 'object'
    ) {

      return Object.keys(value)
        .map(
          key =>
            `${this.formatLabel(key)}: ${this.formatValue(value[key])}`
        )
        .join(' | ');
    }

    return String(value);
  }

  // =====================================================
  // FORMAT LABEL
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
  // FIND VALUE
  // =====================================================

  findValue(
    object: any,
    keys: string[]
  ): any {

    if (
      !object ||
      typeof object !== 'object'
    ) {

      return null;
    }

    for (
      const key of keys
    ) {

      if (
        object[key] !== undefined &&
        object[key] !== null
      ) {

        return object[key];
      }
    }

    /*
     * Case-insensitive fallback.
     */
    const objectKeys =
      Object.keys(object);

    for (
      const wanted of keys
    ) {

      const found =
        objectKeys.find(
          actual =>
            actual.toLowerCase() ===
            wanted.toLowerCase()
        );

      if (found) {

        return object[found];
      }
    }

    return null;
  }

  // =====================================================
  // NETWORK VALUE
  // =====================================================

  findNetworkValue(
    network: any,
    keys: string[]
  ): any {

    if (!network) {
      return null;
    }

    if (Array.isArray(network)) {

      for (
        const item of network
      ) {

        const value =
          this.findValue(
            item,
            keys
          );

        if (
          value !== null &&
          value !== undefined
        ) {

          return value;
        }
      }

      return null;
    }

    return this.findValue(
      network,
      keys
    );
  }

  // =====================================================
  // CHECK HELPERS
  // =====================================================

  cleanValue(
    value: any
  ): string {

    if (
      value === null ||
      value === undefined ||
      value === ''
    ) {

      return 'Not collected';
    }

    return this.formatValue(
      value
    );
  }

  isMissing(
    value: any
  ): boolean {

    if (
      value === null ||
      value === undefined
    ) {

      return true;
    }

    const text =
      String(value)
        .trim()
        .toLowerCase();

    return (
      text === '' ||
      text === 'not collected' ||
      text === 'n/a' ||
      text === 'none' ||
      text === 'null' ||
      text === 'unknown'
    );
  }

  isYes(
    value: any
  ): boolean {

    if (
      value === true
    ) {

      return true;
    }

    const text =
      String(value)
        .trim()
        .toLowerCase();

    return (
      text === 'yes' ||
      text === 'true' ||
      text === 'enabled' ||
      text === 'present' ||
      text === '1'
    );
  }

  isEnabledValue(
    value: any
  ): boolean {

    if (
      this.isYes(value)
    ) {

      return true;
    }

    const text =
      String(value)
        .toLowerCase();

    return (
      text.includes('enabled') &&
      !text.includes('disabled')
    );
  }

  hasSecurityProduct(
    value: any
  ): boolean {

    if (
      this.isMissing(value)
    ) {

      return false;
    }

    const text =
      String(value)
        .toLowerCase();

    return (
      text.includes('defender') ||
      text.includes('antivirus') ||
      text.includes('edr') ||
      text.includes('endpoint') ||
      text.includes('security')
    );
  }

  isUpdateCurrent(
    value: any
  ): boolean {

    if (
      this.isMissing(value)
    ) {

      return false;
    }

    const text =
      String(value)
        .toLowerCase();

    return (
      text.includes('up to date') ||
      text.includes('updated') ||
      text.includes('current') ||
      text.includes('no pending')
    );
  }

  isEncrypted(
    value: any
  ): boolean {

    if (
      this.isMissing(value)
    ) {

      return false;
    }

    const text =
      String(value)
        .toLowerCase();

    return (
      text.includes('encrypted') ||
      text.includes('fully encrypted') ||
      text === 'yes' ||
      text === 'true'
    );
  }

  // =====================================================
  // IDENTITY HELPERS
  // =====================================================

  hasDeviceIdentity(
    identity: any
  ): boolean {

    if (
      !identity ||
      typeof identity !== 'object'
    ) {

      return false;
    }

    const machine =
      this.findValue(
        identity,
        [
          'Machine_GUID',
          'machine_guid',
          'MachineGuid'
        ]
      );

    const smbios =
      this.findValue(
        identity,
        [
          'SMBIOS_UUID',
          'smbios_uuid',
          'SmbiosUuid'
        ]
      );

    return (
      !this.isMissing(machine) &&
      !this.isMissing(smbios)
    );
  }

  getIdentityValue(
    identity: any
  ): string {

    if (
      !identity ||
      typeof identity !== 'object'
    ) {

      return 'Not collected';
    }

    const machine =
      this.findValue(
        identity,
        [
          'Machine_GUID',
          'machine_guid',
          'MachineGuid'
        ]
      );

    const smbios =
      this.findValue(
        identity,
        [
          'SMBIOS_UUID',
          'smbios_uuid',
          'SmbiosUuid'
        ]
      );

    return `Machine GUID: ${
      this.cleanValue(machine)
    } | SMBIOS UUID: ${
      this.cleanValue(smbios)
    }`;
  }

  getTPMValue(
    identity: any
  ): string {

    const present =
      this.findValue(
        identity,
        [
          'TPM_Present',
          'tpm_present',
          'TPMPresent'
        ]
      );

    const version =
      this.findValue(
        identity,
        [
          'TPM_Spec_Version',
          'tpm_spec_version'
        ]
      );

    return `Present: ${
      this.cleanValue(present)
    } | Version: ${
      this.cleanValue(version)
    }`;
  }

  hasTPMInfo(
    identity: any
  ): boolean {

    if (
      !identity ||
      typeof identity !== 'object'
    ) {

      return false;
    }

    const value =
      this.findValue(
        identity,
        [
          'TPM_Present',
          'tpm_present',
          'TPMPresent',
          'TPM_Spec_Version',
          'tpm_spec_version'
        ]
      );

    return !this.isMissing(value);
  }

  // =====================================================
  // NETWORK HELPERS
  // =====================================================

  hasNetwork(
    network: any
  ): boolean {

    return (
      Array.isArray(network)
        ? network.length > 0
        : !!network &&
          typeof network === 'object' &&
          Object.keys(network).length > 0
    );
  }

  getNetworkInterface(
    network: any
  ): string {

    const value =
      this.findNetworkValue(
        network,
        [
          'Interface',
          'interface',
          'Interface_Name',
          'interface_name'
        ]
      );

    return this.cleanValue(
      value
    );
  }

  getMACAddress(
    network: any
  ): string {

    const value =
      this.findNetworkValue(
        network,
        [
          'MAC_Address',
          'mac_address',
          'MAC',
          'mac'
        ]
      );

    return this.cleanValue(
      value
    );
  }

  // =====================================================
  // SOFTWARE HELPERS
  // =====================================================

  hasSoftware(
    software: any
  ): boolean {

    if (
      Array.isArray(software)
    ) {

      return software.length > 0;
    }

    return (
      !!software &&
      typeof software === 'object' &&
      Object.keys(software).length > 0
    );
  }

  getSoftwareCount(
    software: any
  ): string {

    if (
      Array.isArray(software)
    ) {

      return `${software.length} software item(s)`;
    }

    if (
      software &&
      typeof software === 'object'
    ) {

      return `${Object.keys(software).length} software item(s)`;
    }

    return 'Not collected';
  }

  // =====================================================
  // GENERATE AUDIT ID
  // =====================================================

  generateAuditId(): string {

    const now =
      new Date();

    const date =
      now
        .toISOString()
        .replace(/[-:TZ.]/g, '')
        .slice(0, 14);

    return `AUD-${date}-${this.asset?.id || 0}`;
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
        'Endpoint Security Audit Report',

      generated_at:
        new Date().toISOString(),

      endpoint:
        this.asset,

      audit:
        this.auditResult
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
      `${
        this.asset.hostname ||
        'endpoint'
      }-audit-report.json`;

    link.click();

    window.URL.revokeObjectURL(
      url
    );
  }

  // =====================================================
  // BACK
  // =====================================================

  backToInventory(): void {

    this.router.navigate([
      '/inventory'
    ]);
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

    this.router.navigate([
      '/login'
    ]);
  }
}