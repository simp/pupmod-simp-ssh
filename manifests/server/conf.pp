# @summary Sets up sshd_config and adds an iptables rule if iptables is being used.
#
# ``sshd`` configuration variables can be set using Augeas outside of this
# class with no adverse effects.
#
#### SSH Parameters ####
#
# @param acceptenv
#   Specifies what environment variables sent by the client will be copied into
#   the sessions environment.
#
# @param allowgroups
#   A list of group name patterns. If specified, login is allowed only for
#   users whose primary or supplementary group list matches one of the
#   patterns.
#
# @param allowusers
#   A list of user name patterns. If specified, login is allowed only for users
#   whose name matches one of the patterns.
#
# @param authorizedkeysfile
#   This is set to a non-standard location to provide for increased control
#   over who can log in as a given user.
#
# @param authorizedkeyscommand
#   Specifies a program to be used for lookup of the user's public keys.
#
# @param authorizedkeyscommanduser
#   Specifies the user under whose account the AuthorizedKeysCommand is run.
#
# @param banner
#   The contents of the specified file are sent to the remote user before
#   authentication is allowed.
#
# @param challengeresponseauthentication
#   Specifies whether challenge-response authentication is allowed.
#
# @param ciphers
#   Specifies the ciphers allowed for protocol version 2.  When unset, a strong
#   set of ciphers is automatically selected by this class, taking into account
#   whether the server is in FIPS mode.
#
# @param clientalivecountmax
#   @see man page for sshd_config
#
# @param clientaliveinterval
#   @see man page for sshd_config
#
# @param compression
#   Specifies whether compression is allowed, or delayed until the user has
#   authenticated successfully.
#
# @param denygroups
#   A list of group name patterns.  If specified, login is disallowed for users
#   whose primary or supplementary group list matches one of the patterns.
#
# @param denyusers
#   A list of user name patterns.  If specified, login is disallowed for users
#   whose name matches one of the patterns.
#
# @param gssapiauthentication
#   Specifies whether user authentication based on GSSAPI is allowed. If the
#   system is connected to an IPA domain, this will be default to true, based
#   on the existance of the `ipa` fact.
#
# @param hostbasedauthentication
#   @see man page for sshd_config
#
# @param ignorerhosts
#   @see man page for sshd_config
#
# @param ignoreuserknownhosts
#   @see man page for sshd_config
#
# @param kerberosauthentication
#   @see man page for sshd_config
#
# @param kex_algorithms
#   Specifies the key exchange algorithms accepted.  When unset, an appropriate
#   set of algorithms is automatically selected by this class, taking into
#   account whether the server is in FIPS mode and whether the version of
#   openssh installed supports this feature.
#
# @param listenaddress
#   Specifies the local addresses sshd should listen on.
#
# @param logingracetime
#   The max number of seconds the server will wait for a successful login
#   before disconnecting. If the value is 0, there is no limit.
#
# @param ssh_loglevel
#   Specifies the verbosity level that is used when logging messages from sshd.
#
# @param macs
#   Specifies the available MAC algorithms. When unset, a strong set of ciphers
#   is automatically selected by this class, taking into account whether the
#   server is in FIPS mode.
#
# @param maxauthtries
#   Specifies the maximum number of authentication attempts permitted per
#   connection.
#
# @param passwordauthentication
#   Specifies whether password authentication is allowed on the sshd server.
#
#   * This setting must be managed by default so that switching to and from
#     OATH does not lock you out of your system.
#
# @param permitemptypasswords
#   When password authentication is allowed, it specifies whether the server
#   allows login to accounts with empty password strings.
#
# @param permitrootlogin
#   Specifies whether root can log in using SSH.
#
# @param permituserenvironment
#   @see man page for sshd_config
#
# @param port
#   Specifies the port number SSHD listens on.
#
# @param printlastlog
#   Specifies whether SSHD should print the date and time of the last user
#   login when a user logs in interactively.
#
# @param protocol
#   @see man page for sshd_config
#
# @param rhostsrsaauthentication
#   This sshd option has been completely removed in openssh 7.4 and
#   will cause an error message to be logged, when present.  On systems
#   using openssh 7.4 or later, only set this value if you need
#   `RhostsRSAAuthentication` to be in the sshd configuration file to
#   satisfy an outdated, STIG check.
#
# @param strictmodes
#   @see man page for sshd_config
#
# @param subsystem
#   Configures an external subsystem for file transfers.
#
# @param syslogfacility
#   Gives the facility code that is used when logging messages.
#
# @param tcpwrappers
#   If true, enable sshd tcpwrappers.
#
# @param usepam
#   Enables the Pluggable Authentication Module interface.
#
# @param oath
#   **EXPERIMENTAL FEATURE**
#   Configures ssh to use pam_oath TOTP in the sshd pam stack.
#   Also configures sshd_config to use required settings. Inherits from
#   simp_options::oath, defaults to false if not found.
#
# @param manage_pam_sshd
#   Flag indicating whether or not to manage the pam stack for sshd. This is
#   required for the `oath` option to work properly.
#
# @param oath_window
#   Sets the TOTP window (Defined in RFC 6238 section 5.2)
#
# @param oath_key_only_users
#   Users in this list will bypass the password prompt and be prompted for an
#   OATH token followed by authentication using their SSH key.
#
# @param oath_key_only_groups
#   Groups in this list will bypass the password prompt and be prompted for an
#   OATH token followed by authentication using their SSH key.
#
# @param useprivilegeseparation
#   Specifies whether sshd separates privileges by creating an unprivileged
#   child process to deal with incoming network traffic.
#
#   This option has no effect on OpenSSH >= 7.5.0 due to being deprecated.
#
# @param x11forwarding
#   Specifies whether X11 forwarding is permitted.
#
#### Custom Parameters ####
#
# @param custom_entries
#   A Hash of key/value pairs that will be added as ``sshd_config`` resources
#   without any validation.
#
#   * NOTE: Due to complexity, ``Match`` entries are not supported and will
#     need to be added using ``sshd_config_match`` resources as described in
#     ``augeasproviders_ssh``
#
#   @example Set AuthorizedPrincipalsCommand
#     ---
#     ssh::server::conf::custom_entries:
#       AuthorizedPrincipalsCommand: '/usr/local/bin/my_auth_command'
#
# @param remove_entries
#   List of configuration parameters that will be removed.
#
#   * NOTE: Due to complexity, ``Match`` entries are not supported and will
#     need to be removed using ``sshd_config_match`` resources as described in
#     ``augeasproviders_ssh``
#
# @param remove_subsystems
#   List of subsystems that will be removed.
#
#### SIMP Parameters ####
#
# @param app_pki_external_source
#   * If pki = 'simp' or true, this is the directory from which certs will be
#     copied, via pki::copy.  Defaults to /etc/pki/simp/x509.
#
#   * If pki = false, this variable has no effect.
#
# @param app_pki_key
#   Path and name of the private SSL key file. This key file is used to generate
#   the system SSH certificates for consistency.
#
# @param enable_fallback_ciphers
#   If true, add the fallback ciphers from ssh::server::params to the cipher
#   list. This is intended to provide compatibility with non-SIMP systems in a
#   way that properly supports FIPS 140-2.
#
# @param fallback_ciphers
#   The set of ciphers that should be used should no other cipher be declared.
#   This is used when $ssh::server::conf::enable_fallback_ciphers is enabled.
#
# @param fips
#   If set or FIPS is already enabled, adjust for FIPS mode.
#
# @param firewall
#   If true, use the SIMP iptables class.
#
# @param haveged
#   If true, include the haveged module to assist with entropy generation.
#
# @param ldap  If true, enable LDAP support on the system. If
#   authorizedkeyscommand is empty, this will set the authorizedkeyscommand to
#   ssh-ldap-wrapper so that SSH public keys can be stored directly in LDAP.
#
# @param pki
#   * If 'simp', include SIMP's pki module and use pki::copy to manage
#     application certs in /etc/pki/simp_apps/sshd/x509
#   * If true, do *not* include SIMP's pki module, but still use pki::copy
#     to manage certs in /etc/pki/simp_apps/sshd/x509
#   * If false, do not include SIMP's pki module and do not use pki::copy
#     to manage certs.  You will need to appropriately assign a subset of:
#     * app_pki_dir
#     * app_pki_key
#     * app_pki_cert
#     * app_pki_ca
#     * app_pki_ca_dir
#
# @param sssd
#   If true, use sssd
#
# @param ensure_sssd_packages
#   A list of SSSD-related packages to ensure are installed on the system.
#
#   * Set to `false` to prevent package management.
#
# @param trusted_nets  The networks to allow to connect to SSH.
#
# @author https://github.com/simp/pupmod-simp-ssh/graphs/contributors
#
class ssh::server::conf (
#### SSH Parameters ####
  Array[String]                                          $acceptenv                       = $ssh::server::params::acceptenv,
  Optional[Array[String]]                                $allowgroups                     = undef,
  Optional[Array[String]]                                $allowusers                      = undef,
  String                                                 $authorizedkeysfile              = '/etc/ssh/local_keys/%u',
  Optional[Stdlib::Absolutepath]                         $authorizedkeyscommand           = undef,
  String                                                 $authorizedkeyscommanduser       = 'nobody',
  Stdlib::Absolutepath                                   $banner                          = '/etc/issue.net',
  Boolean                                                $challengeresponseauthentication = false,
  Optional[Array[String]]                                $ciphers                         = undef,
  Integer                                                $clientalivecountmax             = 0,
  Integer                                                $clientaliveinterval             = 600,
  Variant[Boolean,Enum['delayed']]                       $compression                     = 'delayed',
  Optional[Array[String]]                                $denygroups                      = undef,
  Optional[Array[String]]                                $denyusers                       = undef,
  Boolean                                                $gssapiauthentication            = $ssh::server::params::gssapiauthentication,
  Boolean                                                $hostbasedauthentication         = false,
  Boolean                                                $ignorerhosts                    = true,
  Boolean                                                $ignoreuserknownhosts            = true,
  Boolean                                                $kerberosauthentication          = false,
  Optional[Array[String]]                                $kex_algorithms                  = undef,
  Optional[Variant[Simplib::Host, Array[Simplib::Host]]] $listenaddress                   = undef,
  Integer[0]                                             $logingracetime                  = 120,
  Optional[Ssh::Loglevel]                                $ssh_loglevel                    = undef,
  Optional[Array[String]]                                $macs                            = undef,
  Integer[1]                                             $maxauthtries                    = 6,
  Boolean                                                $usepam                          = simplib::lookup('simp_options::pam', { 'default_value' => true }),
  Boolean                                                $passwordauthentication          = true,
  Boolean                                                $permitemptypasswords            = false,
  Ssh::PermitRootLogin                                   $permitrootlogin                 = false,
  Boolean                                                $permituserenvironment           = false,
  Variant[Array[Simplib::Port],Simplib::Port]            $port                            = 22,
  Boolean                                                $printlastlog                    = false,
  Array[Integer[1,2]]                                    $protocol                        = [2],
  Optional[Boolean]                                      $rhostsrsaauthentication         = $ssh::server::params::rhostsrsaauthentication,
  Boolean                                                $strictmodes                     = true,
  String                                                 $subsystem                       = 'sftp /usr/libexec/openssh/sftp-server',
  Ssh::Syslogfacility                                    $syslogfacility                  = 'AUTHPRIV',
  Boolean                                                $tcpwrappers                     = simplib::lookup('simp_options::tcpwrappers', { 'default_value' => false }),
  Variant[Boolean,Enum['sandbox']]                       $useprivilegeseparation          = 'sandbox',
  Boolean                                                $x11forwarding                   = false,
  Optional[Hash[String[1],NotUndef]]                     $custom_entries                  = undef,
  Optional[Array[String[1]]]                             $remove_entries                  = undef,
  Optional[Array[String[1]]]                             $remove_subsystems               = undef,

#### SIMP parameters ####
  String                                                 $app_pki_external_source         = simplib::lookup('simp_options::pki::source', { 'default_value' => '/etc/pki/simp/x509' }),
  Stdlib::Absolutepath                                   $app_pki_key                     = "/etc/pki/simp_apps/sshd/x509/private/${facts['fqdn']}.pem",
  Boolean                                                $enable_fallback_ciphers         = true,
  Array[String]                                          $fallback_ciphers                = $ssh::server::params::fallback_ciphers,
  Boolean                                                $fips                            = simplib::lookup('simp_options::fips', { 'default_value' => false }),
  Boolean                                                $firewall                        = simplib::lookup('simp_options::firewall', { 'default_value' => false }),
  Boolean                                                $haveged                         = simplib::lookup('simp_options::haveged', { 'default_value' => false }),
  Boolean                                                $ldap                            = simplib::lookup('simp_options::ldap', { 'default_value' => false }),
  Boolean                                                $oath                            = simplib::lookup('simp_options::oath', { 'default_value' => false }),
  Boolean                                                $manage_pam_sshd                 = $oath,
  Integer[0]                                             $oath_window                     = 1,
  Array[String[1]]                                       $oath_key_only_users             = [],
  Array[String[1]]                                       $oath_key_only_groups            = [],
  Variant[Enum['simp'],Boolean]                          $pki                             = simplib::lookup('simp_options::pki', { 'default_value' => false }),
  Boolean                                                $sssd                            = simplib::lookup('simp_options::sssd', { 'default_value' => false }),
  Variant[Boolean,Array[String[1]]]                      $ensure_sssd_packages            = ['sssd-common'],
  Simplib::Netlist                                       $trusted_nets                    = ['ALL']
) inherits ssh::server::params {
  assert_private()

  $_ports = flatten([$port])

  if $haveged {
    simplib::assert_optional_dependency($module_name, 'simp/haveged')

    include 'haveged'
  }

  if $authorizedkeyscommand {
    if !$authorizedkeyscommanduser or empty($authorizedkeyscommanduser) {
      fail('$authorizedkeyscommanduser must be set if $authorizedkeyscommand is set')
    }
  }

  if $pki {
    simplib::assert_optional_dependency($module_name, 'simp/pki')

    pki::copy { 'sshd':
      source => $app_pki_external_source,
      pki    => $pki,
    }
  }

  if $ldap {
    if $sssd {
      $_use_ldap = false
    }
    else {
      $_use_ldap = $ldap
    }
  }
  else {
    $_use_ldap = $ldap
  }

  if $macs and !empty($macs) {
    $_macs = $macs
  }
  else {
    if $fips or $facts['fips_enabled'] {
      $_macs = $ssh::server::params::fips_macs
    }
    else {
      $_macs = $ssh::server::params::macs
    }
  }

  $_protocol = $protocol.unique.join(',')

  if $ciphers and !empty($ciphers) {
    $_main_ciphers = $ciphers
  }
  else {
    if $fips or $facts['fips_enabled'] {
      $_main_ciphers = $ssh::server::params::fips_ciphers
    }
    else {
      $_main_ciphers = $ssh::server::params::ciphers
    }
  }

  if $enable_fallback_ciphers {
    $_ciphers = unique(flatten([$_main_ciphers,$fallback_ciphers]))
  }
  else {
    $_ciphers = $_main_ciphers
  }

  if $kex_algorithms and !empty($kex_algorithms) {
    $_kex_algorithms = $kex_algorithms
  }
  else {
    if $fips or $facts['fips_enabled'] {
      $_kex_algorithms = $ssh::server::params::fips_kex_algorithms
    }
    else {
      $_kex_algorithms = $ssh::server::params::kex_algorithms
    }
  }

  if $oath {
    $_usepam = true
  }
  else {
    $_usepam = $usepam
  }

  if $_usepam {
    if $oath {
      simplib::assert_optional_dependency($module_name, 'simp/oath')

      include 'oath'

      $_challengeresponseauthentication = true
      $_passwordauthentication = false

      unless empty($oath_key_only_groups) {
        file { '/etc/liboath/ssh_pubkey_groups.oath':
          ensure  => 'file',
          content => "${oath_key_only_groups.sort.join("\n")}\n"
        }

        $_key_only_group_match = "Group ${oath_key_only_groups.join(',')}"

        sshd_config_match { $_key_only_group_match: ensure => 'present' }
        sshd_config { 'AuthenticationMethods for OATH Key Groups':
          ensure    => 'present',
          condition => $_key_only_group_match,
          key       => 'AuthenticationMethods',
          value     => 'publickey,keyboard-interactive'
        }
      }

      unless empty($oath_key_only_users) {
        file { '/etc/liboath/ssh_pubkey_users.oath':
          ensure  => 'file',
          content => "${oath_key_only_users.sort.join("\n")}\n"
        }

        $_key_only_user_match = "User ${oath_key_only_users.join(',')}"

        sshd_config_match { $_key_only_user_match: ensure => 'present' }
        sshd_config { 'AuthenticationMethods for OATH Key Users':
          ensure    => 'present',
          condition => $_key_only_user_match,
          key       => 'AuthenticationMethods',
          value     => 'publickey,keyboard-interactive'
        }
      }
    }

    if $manage_pam_sshd {
      file { '/etc/pam.d/sshd':
        ensure  => file,
        content => epp('ssh/etc/pam.d/sshd.epp',
          {
            'enable_oath' => $oath,
            'oath_window' => $oath_window
          }
        )
      }
    }
  }

  file { '/etc/ssh/sshd_config':
    owner  => 'root',
    group  => 'root',
    mode   => '0600',
    notify => Service['sshd']
  }

  ssh::add_sshd_config('AcceptEnv', $acceptenv, $remove_entries)
  ssh::add_sshd_config('AllowGroups', $allowgroups, $remove_entries)
  ssh::add_sshd_config('AllowUsers', $allowusers, $remove_entries)
  if $authorizedkeyscommand {
    ssh::add_sshd_config('AuthorizedKeysCommand', $authorizedkeyscommand, $remove_entries)
    ssh::add_sshd_config('AuthorizedKeysCommandUser', $authorizedkeyscommanduser, $remove_entries)
  }
  elsif $sssd {
    if $ensure_sssd_packages {
      if $ensure_sssd_packages =~ Array {
        $_sssd_packages = $ensure_sssd_packages
      }
      else {
        $_sssd_packages = ['sssd-common']
      }

      ensure_packages($ensure_sssd_packages)
    }

    ssh::add_sshd_config('AuthorizedKeysCommand', '/usr/bin/sss_ssh_authorizedkeys', $remove_entries)
    ssh::add_sshd_config('AuthorizedKeysCommandUser', $authorizedkeyscommanduser, $remove_entries)
  }
  elsif $_use_ldap {
    ssh::add_sshd_config('AuthorizedKeysCommand', '/usr/libexec/openssh/ssh-ldap-wrapper', $remove_entries)
    ssh::add_sshd_config('AuthorizedKeysCommandUser', $authorizedkeyscommanduser, $remove_entries)
  }
  ssh::add_sshd_config('AuthorizedKeysFile', $authorizedkeysfile, $remove_entries)
  ssh::add_sshd_config('Banner', $banner, $remove_entries)
  ssh::add_sshd_config('ChallengeResponseAuthentication', ssh::config_bool_translate(defined('$_challengeresponseauthentication') ? { true => $_challengeresponseauthentication, default => $challengeresponseauthentication } ), $remove_entries)
  ssh::add_sshd_config('Ciphers', $_ciphers, $remove_entries)
  ssh::add_sshd_config('ClientAliveInterval', String($clientaliveinterval), $remove_entries)
  ssh::add_sshd_config('ClientAliveCountMax', String($clientalivecountmax), $remove_entries)
  ssh::add_sshd_config('Compression', ssh::config_bool_translate($compression), $remove_entries)
  ssh::add_sshd_config('DenyGroups', $denygroups, $remove_entries)
  ssh::add_sshd_config('DenyUsers', $denyusers, $remove_entries)
  ssh::add_sshd_config('GSSAPIAuthentication', ssh::config_bool_translate($gssapiauthentication), $remove_entries)
  ssh::add_sshd_config('HostbasedAuthentication', ssh::config_bool_translate($hostbasedauthentication), $remove_entries)
  ssh::add_sshd_config('KerberosAuthentication', ssh::config_bool_translate($kerberosauthentication), $remove_entries)
  # Kex should be empty openssl < 5.7, they are not supported.
  if !empty($_kex_algorithms) {
    ssh::add_sshd_config('KexAlgorithms', $_kex_algorithms, $remove_entries)
  }
  ssh::add_sshd_config('IgnoreRhosts', ssh::config_bool_translate($ignorerhosts), $remove_entries)
  ssh::add_sshd_config('IgnoreUserKnownHosts', ssh::config_bool_translate($ignoreuserknownhosts), $remove_entries)
  if $listenaddress {
    ssh::add_sshd_config('ListenAddress', $listenaddress, $remove_entries)
  }
  ssh::add_sshd_config('LoginGraceTime', $logingracetime, $remove_entries)
  ssh::add_sshd_config('LogLevel', $ssh_loglevel, $remove_entries)
  ssh::add_sshd_config('MACs', $_macs, $remove_entries)
  ssh::add_sshd_config('MaxAuthTries', $maxauthtries, $remove_entries)
  ssh::add_sshd_config('PasswordAuthentication', ssh::config_bool_translate(defined('$_passwordauthentication') ? { true => $_passwordauthentication, default => $passwordauthentication} ), $remove_entries)
  ssh::add_sshd_config('PermitEmptyPasswords', ssh::config_bool_translate($permitemptypasswords), $remove_entries)
  ssh::add_sshd_config('PermitRootLogin', ssh::config_bool_translate($permitrootlogin), $remove_entries)
  ssh::add_sshd_config('PermitUserEnvironment', ssh::config_bool_translate($permituserenvironment), $remove_entries)
  ssh::add_sshd_config('Port', $_ports, $remove_entries)
  ssh::add_sshd_config('PrintLastLog', ssh::config_bool_translate($printlastlog), $remove_entries)
  ssh::add_sshd_config('Protocol', $_protocol, $remove_entries)
  if $rhostsrsaauthentication != undef {
    ssh::add_sshd_config('RhostsRSAAuthentication', ssh::config_bool_translate($rhostsrsaauthentication), $remove_entries)
  }
  ssh::add_sshd_config('StrictModes', ssh::config_bool_translate($strictmodes), $remove_entries)
  ssh::add_sshd_config('SyslogFacility', $syslogfacility, $remove_entries)
  ssh::add_sshd_config('UsePAM', ssh::config_bool_translate(defined('$_usepam') ? { true => $_usepam, default => $usepam } ), $remove_entries)
  ssh::add_sshd_config('X11Forwarding', ssh::config_bool_translate($x11forwarding), $remove_entries)

  # Version dependent items
  if versioncmp($facts['openssh_version'], '7.5') < 0 {
    ssh::add_sshd_config('UsePrivilegeSeparation', ssh::config_bool_translate($useprivilegeseparation), $remove_entries)
  }
  elsif !$remove_entries or ($remove_entries and !('UsePrivilegeSeparation' in $remove_entries)) {
    sshd_config { 'UsePrivilegeSeparation': ensure =>  absent }
  }

  # Custom manipulation
  if $custom_entries {
    $custom_entries.each |$key, $value| {
      sshd_config { $key: value => $value }
    }
  }

  if $remove_entries {
    $remove_entries.unique.each |$key| { sshd_config { $key: ensure => absent } }
  }

  $subsystem_array = split($subsystem, ' +')
  sshd_config_subsystem { $subsystem_array[0]: command => join($subsystem_array[1,-1], ' ') }

  if $remove_subsystems {
    $remove_subsystems.unique.each |$subsystem| {
      sshd_config_subsystem { $subsystem: ensure => absent }
    }
  }

  file { '/etc/ssh/local_keys':
    ensure  => 'directory',
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    recurse => true,
  }

  $_ports.each |Simplib::Port $sel_port| {
    if ($sel_port != 22) and $facts['selinux_enforced'] {
      if simplib::module_exist('simp/selinux') {
        simplib::assert_optional_dependency($module_name, 'simp/selinux')
        simplib::assert_optional_dependency($module_name, 'simp/vox_selinux')

        include vox_selinux

      }
      else {
        simplib::assert_optional_dependency($module_name, 'puppet/selinux')
        include selinux
      }

      selinux_port { "tcp_${sel_port}-${sel_port}":
        low_port  => $sel_port,
        high_port => $sel_port,
        seltype   => 'ssh_port_t',
        protocol  => 'tcp'
      }
    }
  }

  if $firewall {
    simplib::assert_optional_dependency($module_name, 'simp/iptables')

    include 'iptables'

    iptables::listen::tcp_stateful { 'allow_sshd':
      order        => 8,
      trusted_nets => $trusted_nets,
      dports       => $_ports,
    }
  }

  if $tcpwrappers {
    simplib::assert_optional_dependency($module_name, 'simp/tcpwrappers')

    include 'tcpwrappers'

    tcpwrappers::allow { 'sshd':
      pattern => simplib::nets2ddq($trusted_nets),
      order   => 1
    }
  }
}
