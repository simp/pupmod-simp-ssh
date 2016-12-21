# class ssh::server::conf
#
# Sets up sshd_config and adds an iptables rule if iptables is being used.
#
# sshd configuration variables can be set using Augeas outside of this class
# with no adverse effects.
#
# @param acceptenv  Specifies what environment variables sent by the
#   client will be copied into the sessions environment.
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
# @param compression Specifies whether compression is allowed, or
#   delayed until the user has authenticated successfully.
#
# @param fallback_ciphers  The set of ciphers that should be used should
#   no other cipher be declared. This is used when
#   $::ssh::server::conf::enable_fallback_ciphers is enabled.
#
# @param enable_fallback_ciphers  If true, add the fallback ciphers
#   from ssh::server::params to the cipher list. This is intended to provide
#   compatibility with non-SIMP systems in a way that properly supports FIPS
#   140-2.
#
# @param syslogfacility Gives the facility code that is used when
#   logging messages.
#
# @param gssapiauthentication  Specifies whether user authentication
#   based on GSSAPI is allowed.
#
# @param kex_algorithms Specifies the key exchange algorithms accepted.  When
#   unset, an appropriate set of algorithms is automatically selected by this
#   class, taking into account whether the server is in FIPS mode and whether
#   the version of openssh installed supports this feature.
#
# @param listenaddress  Specifies the local addresses sshd should listen on.
#
# @param port  Specifies the port number SSHD listens on.
#
# @param macs  Specifies the available MAC algorithms. When unset, a
#  strong set of ciphers is automatically selected by this class, taking into
#  account whether the server is in FIPS mode.
#
# @param permitemptypasswords  When password authentication is allowed,
#   it specifies whether the server allows login to accounts with empty password
#   strings.
#
# @param permitrootlogin  Specifies whether root can log in using SSH.
#
# @param printlastlog  Specifies whether SSHD should print the date and
#   time of the last user login when a user logs in interactively.
#
# @param subsystem  Configures and external subsystem for file
#   transfers.
#
# @param pam Enables the Pluggable Authentication Module interface.
#
# @param useprivilegeseparation  Specifies whether sshd separates
#   privileges by creating an unprivileged child process to deal with incoming
#   network traffic.
#
# @param x11forwarding  Specifies whether X11 forwarding is permitted.
#
# @param trusted_nets  The networks to allow to connect to SSH.
#
# @param firewall  If true, use the SIMP iptables class.
#
# @param ldap  If true, enable LDAP support on the system. If
#   authorizedkeyscommand is empty, this will set the authorizedkeyscommand to
#   ssh-ldap-wrapper so that SSH public keys can be stored directly in LDAP.
#
# @param tcpwrappers  If true, allow sshd tcpwrapper.
#
# @param haveged  If true, include the haveged module to assist
#   with entropy generation.
#
# @param sssd  If true, use sssd.
#
# @param fips If set or FIPS is already enabled, adjust for FIPS mode.
#
# @param pki  If true, will include 'pki' and then use the certificates that
#   are transferred to generate the system SSH certificates for consistency.
#
# @param app_pki_external_source The pki root directory.  When @p pki is true, the
#   host pki certificate, $app_pki_external_source/private/<host>.pem, is used to
#   generate /etc/ssh/ssh_host_rsa_key.pub.
#
# @author Trevor Vaughan <mailto:tvaughan@onyxpoint.com>
#
class ssh::server::conf (
  Array[String]                     $acceptenv                       = [
    'LANG',
    'LC_CTYPE',
    'LC_NUMERIC',
    'LC_TIME',
    'LC_COLLATE',
    'LC_MONETARY',
    'LC_MESSAGES',
    'LC_PAPER',
    'LC_NAME',
    'LC_ADDRESS',
    'LC_TELEPHONE',
    'LC_MEASUREMENT',
    'LC_IDENTIFICATION',
    'LC_ALL' ],
  String                            $authorizedkeysfile              = '/etc/ssh/local_keys/%u',
  Optional[Stdlib::Absolutepath]    $authorizedkeyscommand           = undef,
  String                            $authorizedkeyscommanduser       = 'nobody',
  Stdlib::Absolutepath              $banner                          = '/etc/issue.net',
  Boolean                           $challengeresponseauthentication = false,
  Optional[Array[String]]           $ciphers                         = undef,
  Array[String]                     $fallback_ciphers                = $::ssh::server::params::fallback_ciphers,
  Boolean                           $enable_fallback_ciphers         = true,
  Variant[Boolean, Enum['delayed']] $compression                     = false,
  Ssh::Syslogfacility               $syslogfacility                  = 'AUTHPRIV',
  Boolean                           $gssapiauthentication            = false,
  Optional[Array[String]]           $kex_algorithms                  = undef,
  Simplib::Host                     $listenaddress                   = '0.0.0.0',
  Simplib::Port                     $port                            = 22,
  Optional[Array[String]]           $macs                            = undef,
  Boolean                           $permitemptypasswords            = false,
  Boolean                           $permitrootlogin                 = false,
  Boolean                           $printlastlog                    = false,
  String                            $subsystem                       = 'sftp /usr/libexec/openssh/sftp-server',
  Boolean                           $pam                             = simplib::lookup('simp_options::pam', { 'default_value' => false }),
  Boolean                           $useprivilegeseparation          = true,
  Boolean                           $x11forwarding                   = false,
  Array[String]                     $trusted_nets                    = simplib::lookup('simp_options::trusted_nets', { 'default_value' => ['127.0.0.1', '::1'] }),
  Boolean                           $firewall                        = simplib::lookup('simp_options::firewall', { 'default_value' => false }),
  Boolean                           $ldap                            = simplib::lookup('simp_options::ldap', { 'default_value' => false }),
  Boolean                           $sssd                            = simplib::lookup('simp_options::sssd', { 'default_value' => false }),
  Boolean                           $haveged                         = simplib::lookup('simp_options::haveged', { 'default_value' => false }),
  Boolean                           $tcpwrappers                     = simplib::lookup('simp_options::tcpwrappers', { 'default_value' => false }),
  Boolean                           $fips                            = simplib::lookup('simp_options::fips', { 'default_value' => false }),
  Boolean                           $pki                             = simplib::lookup('simp_options::pki', { 'default_value' => false }),
  Stdlib::Absolutepath              $app_pki_external_source         = simplib::lookup('simp_options::pki::source', { 'default_value' => '/etc/pki/simp' })
) inherits ::ssh::server::params {
  assert_private()

  validate_net_list($trusted_nets)

  if $authorizedkeyscommand {
    if ( $::operatingsystem in ['RedHat','CentOS','Fedora'] )
      and ( versioncmp($::operatingsystemmajrelease,'6') > 0 )
    {
      if empty($authorizedkeyscommanduser) {
        fail('$authorizedkeyscommanduser must be set if $authorizedkeyscommand is set')
      }
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

  sshd_config{ 'AcceptEnv': value => $acceptenv }
  sshd_config{ 'AuthorizedKeysFile': value => $authorizedkeysfile }
  sshd_config{ 'Banner': value => $banner }
  sshd_config{ 'ChallengeResponseAuthentication': value => ssh_config_bool_translate($challengeresponseauthentication) }
  sshd_config{ 'Ciphers': value => $_ciphers }
  sshd_config{ 'Compression': value => ssh_config_bool_translate($compression) }
  sshd_config{ 'SyslogFacility': value => $syslogfacility}
  sshd_config{ 'GSSAPIAuthentication': value => ssh_config_bool_translate($gssapiauthentication) }
  # Kex should be empty openssl < 5.7, they are not supported.
  if !empty($_kex_algorithms) { sshd_config{ 'KexAlgorithms': value => $_kex_algorithms } }
  sshd_config{ 'ListenAddress': value => $listenaddress }
  sshd_config{ 'Port': value => to_string($port) }
  sshd_config{ 'MACs': value => $_macs }
  sshd_config{ 'PermitEmptyPasswords': value => ssh_config_bool_translate($permitemptypasswords) }
  sshd_config{ 'PermitRootLogin': value => ssh_config_bool_translate($permitrootlogin) }
  sshd_config{ 'PrintLastLog': value => ssh_config_bool_translate($printlastlog) }
  sshd_config{ 'UsePAM': value => ssh_config_bool_translate($pam) }
  sshd_config{ 'UsePrivilegeSeparation': value => ssh_config_bool_translate($useprivilegeseparation) }
  sshd_config{ 'X11Forwarding': value => ssh_config_bool_translate($x11forwarding) }

  if $authorizedkeyscommand {
    sshd_config { 'AuthorizedKeysCommand': value => $authorizedkeyscommand }
    if ( $::operatingsystem in ['RedHat','CentOS','Fedora'] )
      and ( versioncmp($::operatingsystemmajrelease,'6') > 0 )
    {
      sshd_config { 'AuthorizedKeysCommandUser': value => $authorizedkeyscommanduser }
    }
  }
  elsif $sssd{
    include '::sssd::install'

    sshd_config { 'AuthorizedKeysCommand': value => '/usr/bin/sss_ssh_authorizedkeys' }
    if ( $::operatingsystem in ['RedHat','CentOS','Fedora'] )
      and ( versioncmp($::operatingsystemmajrelease,'6') > 0 )
    {
      sshd_config { 'AuthorizedKeysCommandUser': value => $authorizedkeyscommanduser }
    }
  }
  elsif $_use_ldap {
    sshd_config { 'AuthorizedKeysCommand': value => '/usr/libexec/openssh/ssh-ldap-wrapper' }
    if ( $::operatingsystem in ['RedHat','CentOS','Fedora'] )
      and ( versioncmp($::operatingsystemmajrelease,'6') > 0 )
    {
      sshd_config { 'AuthorizedKeysCommandUser': value => $authorizedkeyscommanduser }
    }
    file { '/etc/ssh/ldap.conf':
      ensure => 'file',
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
      source => 'file:///etc/pam_ldap.conf'
    }
  }

  $subsystem_array = split($subsystem, ' +')
  sshd_config_subsystem{ $subsystem_array[0]: command => $subsystem_array[1] }

  file { '/etc/ssh/local_keys':
    ensure  => 'directory',
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    recurse => true
  }

  if $firewall {
    include '::iptables'
    iptables::add_tcp_stateful_listen { 'allow_sshd':
      order        => '8',
      trusted_nets => $trusted_nets,
      dports       => $port
    }
  }

  if $tcpwrappers {
    include '::tcpwrappers'
    tcpwrappers::allow { 'sshd':
      pattern => nets2ddq($trusted_nets),
      order   => '1'
    }
  }

  if $haveged {
    include '::haveged'
  }
}
