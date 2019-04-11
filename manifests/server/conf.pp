# Sets up sshd_config and adds an iptables rule if iptables is being used.
#
# sshd configuration variables can be set using Augeas outside of this class
# with no adverse effects.
#
#### SSH Parameters ####
#
# @param acceptenv  Specifies what environment variables sent by the
#   client will be copied into the sessions environment.
#
# @param allowgroups  A list of group name patterns. If specified, login is
#   allowed only for users whose primary or supplementary group list matches
#   one of the patterns.
#
# @param allowusers  A list of user name patterns. If specified, login is
#   allowed only for users whose name matches one of the patterns.
#
# @param authorizedkeysfile  This is set to a non-standard location to
#   provide for increased control over who can log in as a given user.
#
# @param authorizedkeyscommand  Specifies a program to be used for
#   lookup of the user's public keys.
#
# @param authorizedkeyscommanduser  Specifies the user under whose
#   account the AuthorizedKeysCommand is run.
#
# @param banner  The contents of the specified file are sent to the
#   remote user before authentication is allowed.
#
# @param challengeresponseauthentication  Specifies whether
#   challenge-response authentication is allowed.
#
# @param ciphers  Specifies the ciphers allowed for protocol
#   version 2.  When unset, a strong set of ciphers is automatically
#   selected by this class, taking into account whether the server is
#   in FIPS mode.
#
# @param clientalivecountmax
#   @see man page for sshd_config
#
# @param clientaliveinterval
#   @see man page for sshd_config
#
# @param compression Specifies whether compression is allowed, or
#   delayed until the user has authenticated successfully.
#
# @param denygroups  A list of group name patterns.  If specified, login is
#   disallowed for users whose primary or supplementary group list matches
#   one of the patterns.
#
# @param denyusers  A list of user name patterns.  If specified, login is
#   disallowed for users whose name matches one of the patterns.
#
# @param gssapiauthentication Specifies whether user authentication
#   based on GSSAPI is allowed. If the system is connected to an IPA domain,
#   this will be default to true, based on the existance of the `ipa` fact.
#
# @param hostbasedauthentication
#   @see man page for sshd_config
#
# @param ignorerhosts
#   @see man page for sshd_config
# @param ignoreuserknownhosts
#   @see man page for sshd_config
#
# @param kerberosauthentication
#   @see man page for sshd_config
#
# @param kex_algorithms Specifies the key exchange algorithms accepted.  When
#   unset, an appropriate set of algorithms is automatically selected by this
#   class, taking into account whether the server is in FIPS mode and whether
#   the version of openssh installed supports this feature.
#
# @param listenaddress  Specifies the local addresses sshd should listen on.
#
# @param logingracetime  The max number of seconds the server will wait for a
#   successful login before disconnecting. If the value is 0, there is no
#   limit.
#
# @param ssh_loglevel  Specifies the verbosity level that is used when logging
#   messages from sshd.
#
# @param macs  Specifies the available MAC algorithms. When unset, a
#   strong set of ciphers is automatically selected by this class, taking into
#   account whether the server is in FIPS mode.
#
# @pram maxauthtries  Specifies the maximum number of authentication attempts
#   permitted per connection.
#
# @param passwordauthentication Enable password authentication on the sshd
#   server. If left as undef (default), this setting will not be managed.
#
# @param permitemptypasswords  When password authentication is allowed,
#   it specifies whether the server allows login to accounts with empty password
#   strings.
#
# @param permitrootlogin  Specifies whether root can log in using SSH.
#
# @param permituserenvironment
#   @see man page for sshd_config
#
# @param port  Specifies the port number SSHD listens on.
#
# @param printlastlog  Specifies whether SSHD should print the date and
#   time of the last user login when a user logs in interactively.
#
# @param protocol
#   @see man page for sshd_config
#
# @param rhostsrsaauthentication
#
#   This sshd option has been completely removed in openssh 7.4 and
#   will cause an error message to be logged, when present.  On systems
#   using openssh 7.4 or later, only set this value if you need
#   `RhostsRSAAuthentication` to be in the sshd configuration file to
#   satisfy an outdated, STIG check.
#
# @param strictmodes
#   @see man page for sshd_config
#
# @param subsystem  Configures and external subsystem for file
#   transfers.
#
# @param syslogfacility Gives the facility code that is used when
#   logging messages.
#
# @param tcpwrappers  If true, allow sshd tcpwrapper.
#
# @param usepam Enables the Pluggable Authentication Module interface.
#
# @param useprivilegeseparation  Specifies whether sshd separates
#   privileges by creating an unprivileged child process to deal with incoming
#   network traffic.
#
# @param x11forwarding  Specifies whether X11 forwarding is permitted.
#
#### SIMP parameters ####
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
# @param enable_fallback_ciphers  If true, add the fallback ciphers
#   from ssh::server::params to the cipher list. This is intended to provide
#   compatibility with non-SIMP systems in a way that properly supports FIPS
#   140-2.
#
# @param fallback_ciphers  The set of ciphers that should be used should
#   no other cipher be declared. This is used when
#   $::ssh::server::conf::enable_fallback_ciphers is enabled.
#
# @param fips If set or FIPS is already enabled, adjust for FIPS mode.
#
# @param firewall  If true, use the SIMP iptables class.
#
# @param haveged  If true, include the haveged module to assist
#   with entropy generation.
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
# @param sssd  If true, use sssd.
#
# @param trusted_nets  The networks to allow to connect to SSH.
#

class ssh::server::conf (
#### SSH Parameters ####
  Array[String]                    $acceptenv                       = $::ssh::server::params::acceptenv,
  Optional[Array[String]]          $allowgroups                     = undef,
  Optional[Array[String]]          $allowusers                      = undef,
  String                           $authorizedkeysfile              = '/etc/ssh/local_keys/%u',
  Optional[Stdlib::Absolutepath]   $authorizedkeyscommand           = undef,
  String                           $authorizedkeyscommanduser       = 'nobody',
  Stdlib::Absolutepath             $banner                          = '/etc/issue.net',
  Boolean                          $challengeresponseauthentication = false,
  Optional[Array[String]]          $ciphers                         = undef,
  Integer                          $clientalivecountmax             = 0,
  Integer                          $clientaliveinterval             = 600,
  Variant[Boolean,Enum['delayed']] $compression                     = 'delayed',
  Optional[Array[String]]          $denygroups                      = undef,
  Optional[Array[String]]          $denyusers                       = undef,
  Boolean                          $gssapiauthentication            = $::ssh::server::params::gssapiauthentication,
  Boolean                          $hostbasedauthentication         = false,
  Boolean                          $ignorerhosts                    = true,
  Boolean                          $ignoreuserknownhosts            = true,
  Boolean                          $kerberosauthentication          = false,
  Optional[Array[String]]          $kex_algorithms                  = undef,
  Simplib::Host                    $listenaddress                   = '0.0.0.0',
  Integer[0]                       $logingracetime                  = 120,
  Ssh::Loglevel                    $loglevel                        = 'INFO',
  Optional[Array[String]]          $macs                            = undef,
  Integer[1]                       $maxauthtries                    = 6,
  Boolean                          $usepam                          = simplib::lookup('simp_options::pam', { 'default_value' => true }),
  Optional[Boolean]                $passwordauthentication          = undef,
  Boolean                          $permitemptypasswords            = false,
  Ssh::PermitRootLogin             $permitrootlogin                 = false,
  Boolean                          $permituserenvironment           = false,
  Simplib::Port                    $port                            = 22,
  Boolean                          $printlastlog                    = false,
  Array[Integer[1,2]]              $protocol                        = [2],
  Optional[Boolean]                $rhostsrsaauthentication         = $::ssh::server::params::rhostsrsaauthentication,
  Boolean                          $strictmodes                     = true,
  String                           $subsystem                       = 'sftp /usr/libexec/openssh/sftp-server',
  Ssh::Syslogfacility              $syslogfacility                  = 'AUTHPRIV',
  Boolean                          $tcpwrappers                     = simplib::lookup('simp_options::tcpwrappers', { 'default_value' => false }),
  Variant[Boolean,Enum['sandbox']] $useprivilegeseparation          = $::ssh::server::params::useprivilegeseparation,
  Boolean                          $x11forwarding                   = false,
#### SIMP parameters ####
  String                           $app_pki_external_source         = simplib::lookup('simp_options::pki::source', { 'default_value' => '/etc/pki/simp/x509' }),
  Stdlib::Absolutepath             $app_pki_key                     = "/etc/pki/simp_apps/sshd/x509/private/${facts['fqdn']}.pem",
  Boolean                          $enable_fallback_ciphers         = true,
  Array[String]                    $fallback_ciphers                = $::ssh::server::params::fallback_ciphers,
  Boolean                          $fips                            = simplib::lookup('simp_options::fips', { 'default_value' => false }),
  Boolean                          $firewall                        = simplib::lookup('simp_options::firewall', { 'default_value' => false }),
  Boolean                          $haveged                         = simplib::lookup('simp_options::haveged', { 'default_value' => false }),
  Boolean                          $ldap                            = simplib::lookup('simp_options::ldap', { 'default_value' => false }),
  Variant[Enum['simp'],Boolean]    $pki                             = simplib::lookup('simp_options::pki', { 'default_value' => false }),
  Boolean                          $sssd                            = simplib::lookup('simp_options::sssd', { 'default_value' => false }),
  Simplib::Netlist                 $trusted_nets                    = ['ALL'],
) inherits ::ssh::server::params {
  assert_private()

  $rhel_greater_than_6 = ( $facts['os']['family'] == 'RedHat' ) and ( $facts['os']['release']['major'] > '6' )

  unless $rhel_greater_than_6 {
    if $permitrootlogin == 'prohibit-password' {
      fail('$permitrootlogin may not be "prohibit-password" on EL6')
    }
  }

  if $haveged {
    include '::haveged'
  }

  if $authorizedkeyscommand {
    if $rhel_greater_than_6 {
      if !$authorizedkeyscommanduser or empty($authorizedkeyscommanduser) {
        fail('$authorizedkeyscommanduser must be set if $authorizedkeyscommand is set')
      }
    }
  }

  if $pki {
    pki::copy { 'sshd':
      source => $app_pki_external_source,
      pki    => $pki
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
      $_macs = $::ssh::server::params::fips_macs
    }
    else {
      $_macs = $::ssh::server::params::macs
    }
  }

  $_protocol = $protocol.unique.join(',')

  if $ciphers and !empty($ciphers) {
    $_main_ciphers = $ciphers
  }
  else {
    if $fips or $facts['fips_enabled'] {
      $_main_ciphers = $::ssh::server::params::fips_ciphers
    }
    else {
      $_main_ciphers = $::ssh::server::params::ciphers
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
      $_kex_algorithms = $::ssh::server::params::fips_kex_algorithms
    }
    else {
      $_kex_algorithms = $::ssh::server::params::kex_algorithms
    }
  }

  file { '/etc/ssh/sshd_config':
    owner  => 'root',
    group  => 'root',
    mode   => '0600',
    notify => Service['sshd'],
  }

  sshd_config { 'AcceptEnv'                       : value => $acceptenv }
  sshd_config { 'AllowGroups'                     : value => $allowgroups }
  sshd_config { 'AllowUsers'                      : value => $allowusers }
  if $authorizedkeyscommand {
    sshd_config { 'AuthorizedKeysCommand'         : value => $authorizedkeyscommand }
    if $rhel_greater_than_6 {
      sshd_config { 'AuthorizedKeysCommandUser'   : value => $authorizedkeyscommanduser }
    }
  }
  elsif $sssd {
    include '::sssd::install'

    sshd_config { 'AuthorizedKeysCommand'         : value => '/usr/bin/sss_ssh_authorizedkeys' }
    if $rhel_greater_than_6 {
      sshd_config { 'AuthorizedKeysCommandUser'   : value => $authorizedkeyscommanduser }
    }
  }
  elsif $_use_ldap {
    sshd_config { 'AuthorizedKeysCommand'         : value => '/usr/libexec/openssh/ssh-ldap-wrapper' }
    if $rhel_greater_than_6 {
      sshd_config { 'AuthorizedKeysCommandUser'   : value => $authorizedkeyscommanduser }
    }
  }
  sshd_config { 'AuthorizedKeysFile'              : value => $authorizedkeysfile }
  sshd_config { 'Banner'                          : value => $banner }
  sshd_config { 'ChallengeResponseAuthentication' : value => ssh::config_bool_translate($challengeresponseauthentication) }
  sshd_config { 'Ciphers'                         : value => $_ciphers }
  sshd_config { 'ClientAliveInterval'             : value => String($clientaliveinterval) }
  sshd_config { 'ClientAliveCountMax'             : value => String($clientalivecountmax) }
  sshd_config { 'Compression'                     : value => ssh::config_bool_translate($compression) }
  sshd_config { 'DenyGroups'                      : value => $denygroups }
  sshd_config { 'DenyUsers'                       : value => $denyusers }
  sshd_config { 'GSSAPIAuthentication'            : value => ssh::config_bool_translate($gssapiauthentication) }
  sshd_config { 'HostbasedAuthentication'         : value => ssh::config_bool_translate($hostbasedauthentication) }
  sshd_config { 'KerberosAuthentication'          : value => ssh::config_bool_translate($kerberosauthentication) }
  # Kex should be empty openssl < 5.7, they are not supported.
  if !empty($_kex_algorithms) {
    sshd_config { 'KexAlgorithms'                 : value => $_kex_algorithms }
  }
  sshd_config { 'IgnoreRhosts'                    : value => ssh::config_bool_translate($ignorerhosts) }
  sshd_config { 'IgnoreUserKnownHosts'            : value => ssh::config_bool_translate($ignoreuserknownhosts) }
  sshd_config { 'ListenAddress'                   : value => $listenaddress }
  sshd_config { 'LoginGraceTime'                  : value => $logingracetime }
  sshd_config { 'LogLevel'                        : value => $loglevel }
  sshd_config { 'MACs'                            : value => $_macs }
  sshd_config { 'MaxAuthTries'                    : value => $maxauthtries }
  if $passwordauthentication != undef {
    sshd_config { 'PasswordAuthentication'        : value => ssh::config_bool_translate($passwordauthentication) }
  }
  sshd_config { 'PermitEmptyPasswords'            : value => ssh::config_bool_translate($permitemptypasswords) }
  sshd_config { 'PermitRootLogin'                 : value => ssh::config_bool_translate($permitrootlogin) }
  sshd_config { 'PermitUserEnvironment'           : value => ssh::config_bool_translate($permituserenvironment) }
  sshd_config { 'Port'                            : value => String($port) }
  sshd_config { 'PrintLastLog'                    : value => ssh::config_bool_translate($printlastlog) }
  sshd_config { 'Protocol'                        : value => $_protocol }
  if $rhostsrsaauthentication != undef {
    sshd_config { 'RhostsRSAAuthentication'       : value => ssh::config_bool_translate($rhostsrsaauthentication) }
  }
  sshd_config { 'StrictModes'                     : value => ssh::config_bool_translate($strictmodes) }
  sshd_config { 'SyslogFacility'                  : value => $syslogfacility}
  sshd_config { 'UsePAM'                          : value => ssh::config_bool_translate($usepam) }
  sshd_config { 'UsePrivilegeSeparation'          : value => ssh::config_bool_translate($useprivilegeseparation) }
  sshd_config { 'X11Forwarding'                   : value => ssh::config_bool_translate($x11forwarding) }

  $subsystem_array = split($subsystem, ' +')
  sshd_config_subsystem { $subsystem_array[0]: command => join($subsystem_array[1,-1], " ") }

  file { '/etc/ssh/local_keys':
    ensure  => 'directory',
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    recurse => true
  }

  if $firewall {
    include '::iptables'

    iptables::listen::tcp_stateful { 'allow_sshd':
      order        => 8,
      trusted_nets => $trusted_nets,
      dports       => $port
    }
  }

  if $tcpwrappers {
    include '::tcpwrappers'
    tcpwrappers::allow { 'sshd':
      pattern => simplib::nets2ddq($trusted_nets),
      order   => 1
    }
  }
}
