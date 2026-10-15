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
  last_check_in?: string | null;
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
  manual_count: number;
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
  ) { }
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
      // Always generate a fresh audit from the currently selected
      // endpoint data. This prevents an older cached audit result
      // from hiding fixes to the audit rules.
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
    const asset = this.asset;
    if (!asset) {
      return;
    }
    this.auditLoading = true;
    this.auditError = '';
    try {
      // Build all selected checks directly from the endpoint data
      // already collected by the Windows discovery agent.
      const checks = this.buildAuditChecks();
      const passed = checks.filter(
        check => check.status.toUpperCase() === 'PASS'
      ).length;
      const failed = checks.filter(
        check => check.status.toUpperCase() === 'FAIL'
      ).length;
      const manual = checks.filter(
        check => check.status.toUpperCase() === 'MANUAL REVIEW'
      ).length;
      const evaluated = passed + failed;
      const score = evaluated > 0
        ? Math.round((passed / evaluated) * 100)
        : 0;
      const auditId = this.generateAuditId();
      // Every checklist row belongs to this audit.
      checks.forEach(check => {
        check.audit_id = auditId;
      });
      const result: AuditResult = {
        audit_id: auditId,
        asset_id: asset.id,
        hostname: asset.hostname || 'Unknown',
        operating_system: this.getOSName(),
        os_version: this.getOSVersion(),
        audit_profile: 'Windows Endpoint Security Audit',
        compliance_standard: 'ISMS Security Baseline',
        audit_timestamp: new Date().toISOString(),
        overall_score: score,
        passed_count: passed,
        failed_count: failed,
        manual_count: manual,
        total_checks: checks.length,
        status:
          failed > 0
            ? 'FAILED'
            : manual > 0
              ? 'NEEDS REVIEW'
              : 'PASSED',
        checks
      };
      this.auditResult = result;
      this.auditLoading = false;
      this.auditError = '';
      // Keep the latest generated audit after a page refresh.
      localStorage.setItem(
        `auditResult_${asset.id}`,
        JSON.stringify(result)
      );
      console.log('Audit completed:', result);
    } catch (error) {
      console.error('Audit generation error:', error);
      this.auditLoading = false;
      this.auditResult = null;
      this.auditError = 'Unable to generate the endpoint audit.';
    }
  }
  // =====================================================
  // BUILD SELECTED SECURITY CHECKS
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
    // RETAINED : NETWORK & ENDPOINT SECURITY
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
      this.isFirewallEnabled(firewallValue)
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
      'Antivirus / endpoint protection product detected',
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
      'Explicit EDR status available',
      this.isMissing(edr)
        ? 'Not explicitly collected'
        : this.cleanValue(edr),
      this.isYes(edr)
        ? 'PASS'
        : this.isMissing(edr)
          ? 'MANUAL REVIEW'
          : 'FAIL',
      'HIGH',
      'EDR status is passed only when the endpoint agent explicitly reports an EDR value; antivirus presence is not treated as EDR evidence.'
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
      4,
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
      5,
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
      6,
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
      7,
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
    // ===================================================
    // RETAINED : SYSTEM & HARDENING
    // ===================================================
    addCheck(
      8,
      'Operating System & Update Status',
      'System Security',
      'OS identified with current version and no pending updates',
      `${this.getOSName()} | Version: ${this.getOSVersion()} | Updates: ${this.cleanValue(updateStatus)}`,
      this.isMissing(updateStatus) ||
        this.getOSName() === 'Not collected' ||
        this.getOSVersion() === 'Not collected'
        ? 'MANUAL REVIEW'
        : this.isUpdateCurrent(updateStatus)
          ? 'PASS'
          : 'FAIL',
      'HIGH',
      'Operating system version and Windows Update status are evaluated together. PASS means the collected OS/version is current and no pending updates are reported.'
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
      9,
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
    const manufacturer =
      this.findValue(
        hardware,
        [
          'Manufacturer',
          'manufacturer'
        ]
      );
    const model =
      this.findValue(
        hardware,
        [
          'Model',
          'model'
        ]
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
    // ===================================================
    // RETAINED : IDENTITY / MANAGEMENT / NETWORK
    // ===================================================
    const fqdn =
      this.findValue(
        hostIdentity,
        [
          'FQDN',
          'fqdn'
        ]
      );
    const domain =
      this.findValue(
        hostIdentity,
        [
          'Domain',
          'domain'
        ]
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
      10,
      'Domain Join Status',
      'Identity Management',
      'Domain join status known',
      this.cleanValue(domainJoined),
      this.isMissing(domainJoined)
        ? 'MANUAL REVIEW'
        : 'PASS',
      'MEDIUM',
      'Domain join state is evaluated only when the endpoint data explicitly reports it.'
    );
    // Some agent versions expose Local_Device_Name separately;
    // the current Windows agent always has Hostname, so use it
    // as a safe fallback rather than incorrectly marking the check
    // as missing.
    const localDevice =
      this.findValue(
        hostIdentity,
        [
          'Local_Device_Name',
          'local_device_name',
          'LocalDeviceName'
        ]
      ) ||
      this.findValue(
        hostIdentity,
        [
          'Hostname',
          'hostname'
        ]
      ) ||
      this.asset.hostname;
    addCheck(
      11,
      'Local Device Name',
      'Host Identity',
      'Device name collected',
      this.cleanValue(localDevice),
      this.isMissing(localDevice)
        ? 'MANUAL REVIEW'
        : 'PASS',
      'LOW',
      'Local device name is taken from the explicit local-device field when available, otherwise the collected hostname.'
    );
    const agentVersion =
      this.asset.agent_version;
    addCheck(
      12,
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
    // Prefer the authoritative asset heartbeat timestamp maintained
    // by the backend. Fall back to the management JSON only if the
    // asset does not contain a last_check_in value.
    const lastCheckIn =
      this.asset.last_check_in ||
      this.findManagementValue(
        management,
        [
          'Last_Check_In',
          'last_check_in',
          'LastCheckIn'
        ],
        'ISMS Windows Agent'
      );
    addCheck(
      13,
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
      this.findManagementValue(
        management,
        [
          'MDM_Intune',
          'mdm_intune',
          'MDM',
          'Intune'
        ],
        'MDM / Intune'
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
    // ===================================================
    // RETAINED : SECURITY / INVENTORY
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
    const adminCount =
      Array.isArray(localAdmins)
        ? localAdmins.length
        : this.isMissing(localAdmins)
          ? null
          : 1;
    let adminStatus: 'PASS' | 'FAIL' | 'MANUAL REVIEW';
    if (adminCount === null) {
      adminStatus = 'MANUAL REVIEW';
    } else if (adminCount === 1) {
      adminStatus = 'PASS';
    } else {
      adminStatus = 'FAIL';
    }
    addCheck(
      14,
      'Local Administrator Count',
      'Privilege Management',
      'Exactly one local administrator',
      adminCount === null
        ? 'Not collected'
        : `${adminCount} local administrator(s)`,
      adminStatus,
      'HIGH',
      adminCount === null
        ? 'Local administrator information could not be verified.'
        : adminCount === 1
          ? 'Exactly one local administrator account is present.'
          : `Security policy requires exactly one local administrator; ${adminCount} are present.`
    );
    const tpmPresent = this.findValue(
      deviceIdentity,
      [
        'TPM_Present',
        'tpm_present',
        'TPMPresent'
      ]
    );
    const tpmVersion = this.findValue(
      deviceIdentity,
      [
        'TPM_Spec_Version',
        'tpm_spec_version',
        'TPM_SpecVersion'
      ]
    );
    const tpmStateKnown = !this.isMissing(tpmPresent);
    const tpmVersionKnown = !this.isMissing(tpmVersion);
    let tpmStatus: 'PASS' | 'FAIL' | 'MANUAL REVIEW';
    if (!tpmStateKnown) {
      tpmStatus = 'MANUAL REVIEW';
    } else if (!this.isYes(tpmPresent)) {
      tpmStatus = 'FAIL';
    } else if (!tpmVersionKnown) {
      tpmStatus = 'MANUAL REVIEW';
    } else {
      tpmStatus = 'PASS';
    }
    addCheck(
      15,
      'TPM Status & Specification',
      'Hardware Security',
      'TPM present and specification version available',
      `Present: ${this.cleanValue(tpmPresent)} | Version: ${this.cleanValue(tpmVersion)}`,
      tpmStatus,
      'HIGH',
      tpmStatus === 'PASS'
        ? 'TPM is present and its specification version is available.'
        : tpmStatus === 'FAIL'
          ? 'TPM is not present on the endpoint.'
          : 'TPM information is incomplete and requires manual review.'
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
      16,
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

    // ===================================================
    // WINDOWS SERVICES
    // ===================================================
    const services = this.findValue(
      security,
      [
        'Services',
        'services',
        'Windows_Services',
        'windows_services'
      ]
    ) as any;

    const flaggedServices =
      services &&
        Array.isArray(services.Flagged_Services)
        ? services.Flagged_Services
        : null;

    let serviceStatus: 'PASS' | 'FAIL' | 'MANUAL REVIEW';

    if (flaggedServices === null) {
      serviceStatus = 'MANUAL REVIEW';
    } else if (flaggedServices.length === 0) {
      serviceStatus = 'PASS';
    } else {
      // These services are review candidates, not confirmed violations.
      serviceStatus = 'MANUAL REVIEW';
    }

    const flaggedServiceNames =
      flaggedServices === null
        ? 'Service scan not available'
        : flaggedServices
          .map((service: any) =>
            service.DisplayName || service.Name
          )
          .join(', ');

    addCheck(
      17,
      'Running Services Security Review',
      'Service Security',
      'No unapproved or unnecessary services running',
      flaggedServices === null
        ? 'Service scan not available'
        : flaggedServices.length === 0
          ? 'No configured review candidates detected'
          : `${flaggedServices.length} service(s) require review: ${flaggedServiceNames}`,
      serviceStatus,
      'MEDIUM',
      flaggedServices === null
        ? 'Service scan data is unavailable. Manual review is required.'
        : flaggedServices.length === 0
          ? 'The agent scanned running services and found no configured review candidates. This does not establish that every service is compliant.'
          : 'The agent detected services configured as potential review candidates. Confirm whether each is required before deciding whether remediation is needed.'
    );

    // ===================================================
    // SYSTEM LOCK POLICY — WIN-018
    // ===================================================
    const systemLock = this.findValue(
      security,
      ['System_Lock', 'system_lock', 'SystemLock']
    ) as any;

    const lockData =
      systemLock && typeof systemLock === 'object'
        ? systemLock
        : null;

    const screenSaverEnabled = lockData?.ScreenSaverEnabled;
    const screenSaverSecure = lockData?.ScreenSaverSecure;
    const timeout = lockData?.InactivityTimeoutSeconds;

    const lockEvidenceComplete =
      lockData?.EvidenceAvailable === true &&
      typeof screenSaverEnabled === 'boolean' &&
      typeof screenSaverSecure === 'boolean' &&
      typeof timeout === 'number' &&
      Number.isFinite(timeout) &&
      timeout > 0;

    let lockStatus: 'PASS' | 'FAIL' | 'MANUAL REVIEW';

    if (!lockEvidenceComplete) {
      lockStatus = 'MANUAL REVIEW';
    } else if (
      screenSaverEnabled === false ||
      screenSaverSecure === false ||
      timeout > 900
    ) {
      lockStatus = 'FAIL';
    } else {
      lockStatus = 'PASS';
    }

    const lockObserved = lockData
      ? `Screen saver: ${screenSaverEnabled === null || screenSaverEnabled === undefined ? 'Unknown' : screenSaverEnabled ? 'Enabled' : 'Disabled'} | Password on resume: ${screenSaverSecure === null || screenSaverSecure === undefined ? 'Unknown' : screenSaverSecure ? 'Enabled' : 'Disabled'} | Timeout: ${typeof timeout === 'number' ? `${timeout} seconds` : 'Not collected'}`
      : 'System lock evidence not collected';

    addCheck(
      18,
      'System Lock Policy',
      'Access Control',
      'Screen saver enabled, password required on resume, and timeout within 15 minutes',
      lockObserved,
      lockStatus,
      'HIGH',
      lockStatus === 'PASS'
        ? 'Collected screen-saver settings meet the configured initial audit rule. Effective machine-wide policy should still be verified for production use.'
        : lockStatus === 'FAIL'
          ? 'Collected settings violate the configured initial audit rule.'
          : 'Required screen-lock evidence is missing or incomplete. Verify effective Windows policy before deciding compliance.'
    );

    // ============================================================
    // PASSWORD POLICY - WIN-019 to WIN-020
    // ============================================================
    const passwordPolicy = this.findValue(
      security,
      ['Password_Policy', 'password_policy', 'PasswordPolicy']
    ) as any;
    const passwordEvidenceAvailable = passwordPolicy?.EvidenceAvailable === true;
    const passwordStrengthPass =
      passwordEvidenceAvailable &&
      typeof passwordPolicy?.MinimumPasswordLength === 'number' &&
      passwordPolicy.MinimumPasswordLength >= 8 &&
      passwordPolicy?.PasswordComplexityEnabled === true &&
      typeof passwordPolicy?.PasswordHistorySize === 'number' &&
      passwordPolicy.PasswordHistorySize >= 2;
    const passwordSecurityPass =
      passwordEvidenceAvailable &&
      typeof passwordPolicy?.MaximumPasswordAgeDays === 'number' &&
      passwordPolicy.MaximumPasswordAgeDays > 0 &&
      passwordPolicy.MaximumPasswordAgeDays <= 90 &&
      passwordPolicy?.ReversiblePasswordStorageEnabled === false;
    const passwordChecks = [
      {
        id: 19,
        title: 'Password Strength & Complexity',
        observed: passwordEvidenceAvailable
          ? `Minimum length: ${passwordPolicy.MinimumPasswordLength}; complexity: ${passwordPolicy.PasswordComplexityEnabled}; history: ${passwordPolicy.PasswordHistorySize}`
          : 'Not collected',
        passed: passwordStrengthPass,
        detail: 'Minimum length must be at least 8 characters, complexity must be enabled, and at least 2 previous passwords must be remembered.'
      },
      {
        id: 20,
        title: 'Password Security & Expiration',
        observed: passwordEvidenceAvailable
          ? `Maximum age: ${passwordPolicy.MaximumPasswordAgeDays} days; reversible storage: ${passwordPolicy.ReversiblePasswordStorageEnabled}`
          : 'Not collected',
        passed: passwordSecurityPass,
        detail: 'Maximum password age must be 1–90 days and reversible password storage must be disabled.'
      }
    ];
    for (const item of passwordChecks) {
      const status = !passwordEvidenceAvailable
        ? 'MANUAL REVIEW'
        : item.passed
          ? 'PASS'
          : 'FAIL';
      addCheck(
        item.id,
        item.title,
        'Access Control',
        item.detail,
        item.observed,
        status,
        'HIGH',
        status === 'PASS'
          ? 'Collected password settings meet the initial audit rule.'
          : status === 'FAIL'
            ? 'One or more collected password settings do not meet the initial audit rule.'
            : 'Password policy evidence is missing or incomplete.'
      );
    }

    // NETWORK INTERFACE SECURITY - WIN-021
const securityPosture = this.parseJSON(this.asset.security_posture) || {};
const networkSecurity = securityPosture.Network_Interface_Security;

    const networkEvidenceAvailable = networkSecurity?.EvidenceAvailable === true;
    const physicalInterfaces = Array.isArray(networkSecurity?.PhysicalInterfaces)
      ? networkSecurity.PhysicalInterfaces
      : [];
    const activeInterfaces = physicalInterfaces.filter(
      (adapter: any) => adapter?.Connected === true
    );
    const wifiEnabled = networkSecurity?.WiFiEnabled;
    const bluetoothEnabled = networkSecurity?.BluetoothEnabled;
    const networkPass =
      networkEvidenceAvailable &&
      activeInterfaces.length === 1 &&
      activeInterfaces[0]?.InterfaceType !== 'WiFi' &&
      wifiEnabled === false &&
      bluetoothEnabled === false;
    const networkStatus = !networkEvidenceAvailable ||
      typeof wifiEnabled !== 'boolean' ||
      typeof bluetoothEnabled !== 'boolean'
      ? 'MANUAL REVIEW'
      : networkPass
        ? 'PASS'
        : 'FAIL';
    addCheck(
      21,
      'Network Interface Security',
      'Network Security',
      'Only one physical network interface should be connected; Wi-Fi and Bluetooth must be disabled under this audit rule.',
      networkEvidenceAvailable
        ? `Connected interfaces: ${activeInterfaces.length}; Wi-Fi enabled: ${wifiEnabled}; Bluetooth enabled: ${bluetoothEnabled}`
        : 'Network security evidence not collected',
      networkStatus,
      'HIGH',
      networkStatus === 'PASS'
        ? 'Network interface settings meet the initial audit rule.'
        : networkStatus === 'FAIL'
          ? 'One or more network interface settings violate the initial audit rule.'
          : 'Network interface evidence is missing or incomplete.'
    );


    // USB DEVICE AUTHORIZATION - WIN-022
    const usbStorage = this.parseJSON(this.asset.security_posture)?.USB_Storage;
    const usbEvidenceAvailable = usbStorage?.EvidenceAvailable === true;
    const usbStorageStartValue = usbStorage?.USBStorageStartValue;
    const usbPolicyVerified = usbStorage?.AuthorizedDevicesOnly === true;
    const usbStatus = !usbEvidenceAvailable || typeof usbPolicyVerified !== 'boolean'
      ? 'MANUAL REVIEW'
      : usbPolicyVerified
        ? 'PASS'
        : usbStorageStartValue === 3
          ? 'MANUAL REVIEW'
          : 'FAIL';
    addCheck(
      22,
      'USB Device Authorization',
      'Device Security',
      'Only authorized USB storage devices should be permitted.',
      usbEvidenceAvailable
        ? `USB storage start value: ${usbStorageStartValue}; authorized-device-only policy: ${usbPolicyVerified ? 'verified' : 'not verified'}`
        : 'USB authorization policy evidence not collected',
      usbStatus,
      'HIGH',
      usbStatus === 'PASS'
        ? 'Authorized USB device restrictions are verified.'
        : usbStatus === 'FAIL'
          ? 'Evidence confirms USB storage restrictions do not meet the audit rule.'
          : 'Authorized-device-only USB policy could not be verified.'
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
  // MANAGEMENT VALUE
  // =====================================================
  findManagementValue(
    management: any,
    keys: string[],
    itemName?: string
  ): any {
    if (!management) {
      return null;
    }
    const items = Array.isArray(management)
      ? management
      : [management];
    // If an item name is supplied, prefer that exact management item.
    if (itemName) {
      const namedItem = items.find(
        (item: any) =>
          item &&
          typeof item === 'object' &&
          String(
            this.findValue(item, ['Name', 'name'])
          ).toLowerCase() === itemName.toLowerCase()
      );
      if (namedItem) {
        const value = this.findValue(namedItem, keys);
        if (
          value !== null &&
          value !== undefined
        ) {
          return value;
        }
      }
    }
    // Otherwise search every management item.
    for (const item of items) {
      const value = this.findValue(item, keys);
      if (
        value !== null &&
        value !== undefined
      ) {
        return value;
      }
    }
    return null;
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
    if (Array.isArray(value)) {
      return value.length === 0;
    }
    if (
      typeof value === 'object'
    ) {
      return Object.keys(value).length === 0;
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
  // =====================================================
  // FIREWALL CHECK HELPER
  // =====================================================
  isFirewallEnabled(
    value: any
  ): boolean {
    if (
      value === null ||
      value === undefined
    ) {
      return false;
    }
    // The Windows agent reports Firewall as an array like:
    // [
    //   { Profile: 'Domain',  Enabled: 1 },
    //   { Profile: 'Private', Enabled: 1 },
    //   { Profile: 'Public',  Enabled: 1 }
    // ]
    // All reported profiles must be enabled for WIN-001 to PASS.
    if (Array.isArray(value)) {
      if (value.length === 0) {
        return false;
      }
      return value.every((profile: any) => {
        if (!profile || typeof profile !== 'object') {
          return false;
        }
        const enabled =
          this.findValue(
            profile,
            [
              'Enabled',
              'enabled',
              'Firewall_Enabled',
              'firewall_enabled'
            ]
          );
        return this.isYes(enabled);
      });
    }
    // Also support a single firewall object.
    if (
      typeof value === 'object'
    ) {
      const enabled =
        this.findValue(
          value,
          [
            'Enabled',
            'enabled',
            'Firewall_Enabled',
            'firewall_enabled'
          ]
        );
      if (
        enabled !== null &&
        enabled !== undefined
      ) {
        return this.isYes(enabled);
      }
    }
    // Support simple values such as 'Enabled', true, 1, 'yes'.
    return this.isEnabledValue(value);
  }
  hasSecurityProduct(
    value: any
  ): boolean {
    if (
      this.isMissing(value)
    ) {
      return false;
    }
    // The current Windows agent reports Antivirus_EDR as an
    // object such as:
    // {
    //   DisplayName: 'Windows Defender',
    //   ProductState: 397568,
    //   PathToSignedProductExe: 'windowsdefender://'
    // }
    if (
      typeof value === 'object' &&
      !Array.isArray(value)
    ) {
      const displayName =
        this.findValue(
          value,
          [
            'DisplayName',
            'displayName',
            'Name',
            'name'
          ]
        );
      return !this.isMissing(displayName);
    }
    const text =
      String(value)
        .trim()
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
    // Explicit pending-update reports must fail.
    if (
      text.includes('pending') ||
      text.includes('unable to determine')
    ) {
      return false;
    }
    return (
      text.includes('up to date') ||
      text.includes('updated') ||
      text.includes('current') ||
      text.includes('no updates')
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
    // The Windows agent reports encryption as one object per volume.
    if (Array.isArray(value)) {
      if (value.length === 0) {
        return false;
      }
      return value.every((volume: any) => {
        if (
          !volume ||
          typeof volume !== 'object'
        ) {
          return false;
        }
        const status =
          this.findValue(
            volume,
            [
              'VolumeStatus',
              'volume_status'
            ]
          );
        const percentage =
          this.findValue(
            volume,
            [
              'EncryptionPercentage',
              'encryption_percentage'
            ]
          );
        const protection =
          this.findValue(
            volume,
            [
              'ProtectionStatus',
              'protection_status'
            ]
          );
        const statusText =
          String(status ?? '')
            .toLowerCase();
        const protectionText =
          String(protection ?? '')
            .toLowerCase();
        const percentageNumber =
          Number(percentage);
        return (
          (
            statusText.includes('fullyencrypted') ||
            statusText.includes('fully encrypted')
          ) &&
          (
            !Number.isNaN(percentageNumber)
              ? percentageNumber >= 100
              : true
          ) &&
          (
            protectionText === '' ||
            protectionText.includes('on') ||
            protectionText.includes('enabled') ||
            protectionText === '1'
          )
        );
      });
    }
    if (
      typeof value === 'object'
    ) {
      const status =
        this.findValue(
          value,
          [
            'VolumeStatus',
            'volume_status'
          ]
        );
      if (status !== null && status !== undefined) {
        return this.isEncrypted(status);
      }
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
    return `Machine GUID: ${this.cleanValue(machine)
      } | SMBIOS UUID: ${this.cleanValue(smbios)
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
    return `Present: ${this.cleanValue(present)
      } | Version: ${this.cleanValue(version)
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
      `${this.asset.hostname ||
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