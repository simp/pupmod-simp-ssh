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
# @param manage_authorizedkeysfile
#   This will allow users to opt out of puppet managing their ssh authorized 
#   keys file. If set to false, authorizedkeysfile will be ignored.
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
#   Specifies the ciphers allowed for protocol version 2.  When unset, no
#   `Ciphers` line is managed.  The `simp:defaults` profile supplies a strong,
#   FIPS-aware set.
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
#   Specifies the key exchange algorithms accepted.  When unset, no
#   `KexAlgorithms` line is managed.  The `simp:defaults` profile supplies a
#   FIPS-aware set.
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
#   Specifies the available MAC algorithms. When unset, no `MACs` line is
#   managed.  The `simp:defaults` profile supplies a strong, FIPS-aware set.
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
# @param manage_pam_sshd
#   Flag indicating whether or not to manage the pam stack for sshd. This is
#   required for the oath option to work properly.
#
# @param oath
#   **EXPERIMENTAL FEATURE**
#   Configures ssh to use pam_oath TOTP in the sshd pam stack.
#   Also configures sshd_config to use required settings. Inherits from
#   simp_options::oath, defaults to false if not found.
#
# @param oath_window
#   Sets the TOTP window (Defined in RFC 6238 section 5.2)
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
  Optional[Array[String]]                                $acceptenv                       = undef,
  Optional[Array[String]]                                $allowgroups                     = undef,
  Optional[Array[String]]                                $allowusers                      = undef,
  Boolean                                                $manage_authorizedkeysfile       = true,
  Optional[String]                                       $authorizedkeysfile              = undef,
  Optional[Stdlib::Absolutepath]                         $authorizedkeyscommand           = undef,
  String                                                 $authorizedkeyscommanduser       = 'nobody',
  Optional[Stdlib::Absolutepath]                         $banner                          = undef,
  Optional[Boolean]                                      $challengeresponseauthentication = undef,
  Optional[Array[String]]                                $ciphers                         = undef,
  Optional[Integer]                                      $clientalivecountmax             = undef,
  Optional[Integer]                                      $clientaliveinterval             = undef,
  Optional[Variant[Boolean,Enum['delayed']]]             $compression                     = undef,
  Optional[Array[String]]                                $denygroups                      = undef,
  Optional[Array[String]]                                $denyusers                       = undef,
  Optional[Boolean]                                      $gssapiauthentication            = undef,
  Optional[Boolean]                                      $hostbasedauthentication         = undef,
  Optional[Boolean]                                      $ignorerhosts                    = undef,
  Optional[Boolean]                                      $ignoreuserknownhosts            = undef,
  Optional[Boolean]                                      $kerberosauthentication          = undef,
  Optional[Array[String]]                                $kex_algorithms                  = undef,
  Optional[Variant[Simplib::Host, Array[Simplib::Host]]] $listenaddress                   = undef,
  Optional[Integer[0]]                                   $logingracetime                  = undef,
  Optional[Ssh::Loglevel]                                $ssh_loglevel                    = undef,
  Optional[Array[String]]                                $macs                            = undef,
  Optional[Integer[1]]                                   $maxauthtries                    = undef,
  Optional[Boolean]                                      $usepam                          = undef,
  Optional[Boolean]                                      $passwordauthentication          = undef,
  Optional[Boolean]                                      $permitemptypasswords            = undef,
  Optional[Ssh::PermitRootLogin]                         $permitrootlogin                 = undef,
  Optional[Boolean]                                      $permituserenvironment           = undef,
  Optional[Variant[Array[Simplib::Port],Simplib::Port]]  $port                            = undef,
  Optional[Boolean]                                      $printlastlog                    = undef,
  Optional[Array[Integer[1,2]]]                          $protocol                        = undef,
  Optional[Boolean]                                      $rhostsrsaauthentication         = undef,
  Optional[Boolean]                                      $strictmodes                     = undef,
  Optional[String]                                       $subsystem                       = undef,
  Optional[Ssh::Syslogfacility]                          $syslogfacility                  = undef,
  Boolean                                                $tcpwrappers                     = false,
  Optional[Variant[Boolean,Enum['sandbox']]]             $useprivilegeseparation          = undef,
  Optional[Boolean]                                      $x11forwarding                   = undef,
  Optional[Hash[String[1],NotUndef]]                     $custom_entries                  = undef,
  Optional[Array[String[1]]]                             $remove_entries                  = undef,
  Optional[Array[String[1]]]                             $remove_subsystems               = undef,

#### SIMP parameters ####
  String                                                 $app_pki_external_source         = '/etc/pki/simp/x509',
  Stdlib::Absolutepath                                   $app_pki_key                     = "/etc/pki/simp_apps/sshd/x509/private/${facts['networking']['fqdn']}.pem",
  Boolean                                                $firewall                        = false,
  Boolean                                                $haveged                         = false,
  Boolean                                                $ldap                            = false,
  Boolean                                                $oath                            = false,
  Boolean                                                $manage_pam_sshd                 = $oath,
  Integer[0]                                             $oath_window                     = 1,
  Variant[Enum['simp'],Boolean]                          $pki                             = false,
  Boolean                                                $sssd                            = false,
  Variant[Boolean,Array[String[1]]]                      $ensure_sssd_packages            = ['sssd-common'],
  Simplib::Netlist                                       $trusted_nets                    = ['ALL']
) {
  assert_private()

  # `sshd` service management is opt-in (see ssh::server).  The chroot/perms
  # scaffolding is only declared when the service is managed; `getvar` reads the
  # parent class's setting without erroring when it is absent.  sshd_config
  # changes do not need an explicit `notify` here: when the service is managed,
  # `ssh::server`'s `Service['sshd']` already subscribes to the whole
  # `ssh::server::conf` class.
  $_manage_service = (getvar('ssh::server::service_ensure') =~ NotUndef) or (getvar('ssh::server::service_enable') =~ NotUndef)

  # `Port` is only emitted when explicitly set, but the firewall/SELinux paths
  # still need a concrete port list to work with.
  $_ports = flatten([pick($port, 22)])

  if $haveged {
    simplib::assert_optional_dependency($module_name, 'simp/haveged')

    include 'haveged'
  }

  if $authorizedkeyscommand {
    if empty($authorizedkeyscommanduser) {
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

  # OATH (when enabled) forces challenge/response on and password auth off.
  $_challengeresponseauthentication = $oath ? {
    true    => true,
    default => $challengeresponseauthentication,
  }
  $_passwordauthentication = $oath ? {
    true    => false,
    default => $passwordauthentication,
  }
  $_usepam = $oath ? {
    true    => true,
    default => $usepam,
  }

  # sshd_config expects strings; only convert when the value is actually set so
  # that an unset (undef) parameter declares no resource (reduced blast radius).
  $_clientalivecountmax = $clientalivecountmax =~ NotUndef ? { true => String($clientalivecountmax), default => undef }
  $_clientaliveinterval = $clientaliveinterval =~ NotUndef ? { true => String($clientaliveinterval), default => undef }
  $_logingracetime      = $logingracetime      =~ NotUndef ? { true => String($logingracetime),      default => undef }
  $_maxauthtries        = $maxauthtries        =~ NotUndef ? { true => String($maxauthtries),        default => undef }

  # `Port` is emitted only when explicitly set; the firewall/SELinux paths use
  # the concrete `$_ports` list regardless.
  $_port_value = $port =~ NotUndef ? { true => $_ports, default => undef }

  # sshd_config resource does not treat Protocol as an array
  $_protocol = $protocol =~ NotUndef ? { true => $protocol.unique.join(','), default => undef }

  if $_usepam {
    if $oath {
      simplib::assert_optional_dependency($module_name, 'simp/oath')

      include 'oath'
    }

    if $manage_pam_sshd {
      file { '/etc/pam.d/sshd':
        ensure  => file,
        content => epp('ssh/etc/pam.d/sshd.epp'),
      }
    }
  }

  # The sshd_config file perms are only owned when we manage the service; a bare
  # include leaves /etc/ssh/sshd_config exactly as the package left it.
  if $_manage_service {
    file { '/etc/ssh/sshd_config':
      owner   => 'root',
      group   => 'root',
      mode    => '0600',
      require => Package['openssh-server'],
    }

    file { '/etc/ssh/local_keys':
      ensure  => 'directory',
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      recurse => true,
      require => Package['openssh-server'],
    }
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

      ensure_packages($_sssd_packages)
    }

    ssh::add_sshd_config('AuthorizedKeysCommand', '/usr/bin/sss_ssh_authorizedkeys', $remove_entries)
    ssh::add_sshd_config('AuthorizedKeysCommandUser', $authorizedkeyscommanduser, $remove_entries)
  }
  elsif $_use_ldap {
    ssh::add_sshd_config('AuthorizedKeysCommand', '/usr/libexec/openssh/ssh-ldap-wrapper', $remove_entries)
    ssh::add_sshd_config('AuthorizedKeysCommandUser', $authorizedkeyscommanduser, $remove_entries)
  }
  if $manage_authorizedkeysfile {
    ssh::add_sshd_config('AuthorizedKeysFile', $authorizedkeysfile, $remove_entries)
  }
  ssh::add_sshd_config('Banner', $banner, $remove_entries)
  ssh::add_sshd_config('ChallengeResponseAuthentication', ssh::config_bool_translate($_challengeresponseauthentication), $remove_entries)
  ssh::add_sshd_config('Ciphers', $ciphers, $remove_entries)
  ssh::add_sshd_config('ClientAliveCountMax', $_clientalivecountmax, $remove_entries)
  ssh::add_sshd_config('ClientAliveInterval', $_clientaliveinterval, $remove_entries)
  ssh::add_sshd_config('Compression', ssh::config_bool_translate($compression), $remove_entries)
  ssh::add_sshd_config('DenyGroups', $denygroups, $remove_entries)
  ssh::add_sshd_config('DenyUsers', $denyusers, $remove_entries)
  ssh::add_sshd_config('GSSAPIAuthentication', ssh::config_bool_translate($gssapiauthentication), $remove_entries)
  ssh::add_sshd_config('HostbasedAuthentication', ssh::config_bool_translate($hostbasedauthentication), $remove_entries)
  ssh::add_sshd_config('IgnoreRhosts', ssh::config_bool_translate($ignorerhosts), $remove_entries)
  ssh::add_sshd_config('IgnoreUserKnownHosts', ssh::config_bool_translate($ignoreuserknownhosts), $remove_entries)
  ssh::add_sshd_config('KerberosAuthentication', ssh::config_bool_translate($kerberosauthentication), $remove_entries)
  ssh::add_sshd_config('KexAlgorithms', $kex_algorithms, $remove_entries)
  ssh::add_sshd_config('ListenAddress', $listenaddress, $remove_entries)
  ssh::add_sshd_config('LoginGraceTime', $_logingracetime, $remove_entries)
  ssh::add_sshd_config('LogLevel', $ssh_loglevel, $remove_entries)
  ssh::add_sshd_config('MACs', $macs, $remove_entries)
  ssh::add_sshd_config('MaxAuthTries', $_maxauthtries, $remove_entries)
  ssh::add_sshd_config('PasswordAuthentication', ssh::config_bool_translate($_passwordauthentication), $remove_entries)
  ssh::add_sshd_config('PermitEmptyPasswords', ssh::config_bool_translate($permitemptypasswords), $remove_entries)
  ssh::add_sshd_config('PermitRootLogin', ssh::config_bool_translate($permitrootlogin), $remove_entries)
  ssh::add_sshd_config('PermitUserEnvironment', ssh::config_bool_translate($permituserenvironment), $remove_entries)
  ssh::add_sshd_config('Port', $_port_value, $remove_entries)
  ssh::add_sshd_config('PrintLastLog', ssh::config_bool_translate($printlastlog), $remove_entries)
  ssh::add_sshd_config('Protocol', $_protocol, $remove_entries)
  ssh::add_sshd_config('RhostsRSAAuthentication', ssh::config_bool_translate($rhostsrsaauthentication), $remove_entries)
  ssh::add_sshd_config('StrictModes', ssh::config_bool_translate($strictmodes), $remove_entries)
  ssh::add_sshd_config('SyslogFacility', $syslogfacility, $remove_entries)
  ssh::add_sshd_config('UsePAM', ssh::config_bool_translate($_usepam), $remove_entries)
  ssh::add_sshd_config('UsePrivilegeSeparation', ssh::config_bool_translate($useprivilegeseparation), $remove_entries)
  ssh::add_sshd_config('X11Forwarding', ssh::config_bool_translate($x11forwarding), $remove_entries)

  # Custom manipulation
  if $custom_entries {
    $custom_entries.each |$key, $value| {
      sshd_config { $key:
        value   => $value,
        require => Package['openssh-server'],
      }
    }
  }

  if $remove_entries {
    $remove_entries.unique.each |$key| {
      sshd_config { $key:
        ensure  => absent,
        require => Package['openssh-server'],
      }
    }
  }

  if $subsystem {
    $subsystem_array = split($subsystem, ' +')
    sshd_config_subsystem { $subsystem_array[0]:
      command => join($subsystem_array[1,-1], ' '),
      require => Package['openssh-server'],
    }
  }

  if $remove_subsystems {
    $remove_subsystems.unique.each |$remove_subsystem| {
      sshd_config_subsystem { $remove_subsystem:
        ensure  => absent,
        require => Package['openssh-server'],
      }
    }
  }

  $_ports.each |Simplib::Port $sel_port| {
    if ($sel_port != 22) and $facts['os']['selinux']['enforced'] {
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
