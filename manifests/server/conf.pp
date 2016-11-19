# == Class: ssh::server::conf
#
# Sets up sshd_config and adds an iptables rule if iptables is being used.
#
# == Parameters
#   This variable can be set using Augeas in addition to this location
#   with no adverse effects.
#
#
# @param acceptenv [Array] Specifies what environment variables sent by the
#   client will be copied into the sessions enviornment.
#
# @param authorizedkeysfile [String] This is set to a non-standard location to
#   provide for increased control over who can log in as a given user.
#   /etc/ssh/local_keys/%u
#
# @param authorizedkeyscommand [String] Specifies a program to be used for
#   lookup of the user's public keys.
#
# @param authorizedkeyscommanduser [String] Specifies the user under whose
#   account the AuthorizedKeysCommand is run.
#
# @param banner [String] The contents of the specified file are sent to the
#   remote user before authentication is allowed.
#
# @param challengeresponseauthentication [Boolean] Specifies whether
#   challenge-response authentication is allowed.
#
# @param ciphers [Array] Specifies the ciphers allowed for protocol version 2.
#
# @param compression [String] Specifies whether compression is allowed, or
#   delayed until the user has authenticated successfully.
#
# @param fallback_ciphers [Array] The set of ciphers that should be used should
#   no other cipher be declared. This is used when
#   $::ssh::server::enable_fallback_ciphers is enabled.
#
# @param enable_fallback_ciphers [Boolean] If true, add the fallback ciphers
#from ssh::server::params to the cipher list. This is intended to provide
#   compatibility with non-SIMP systems in a way that properly supports FIPS
#   140-2.
#
# @param syslogfacility [String] Gives the facility code that is used when
#   logging messages. Valid Options: 'DAEMON', 'USER', 'AUTH', 'AUTHPRIV',
#   'LOCAL0', 'LOCAL1', 'LOCAL2', 'LOCAL3', 'LOCAL4', 'LOCAL5', 'LOCAL6',
#   'LOCAL7'.
#
# @param gssapiauthentication [Boolean] Specifies whether user authentication
#   based on GSSAPI is allowed.
#
# @param kex_algorithms [Array]
#
# @param listenaddress [String] Specifies the local addresses sshd should listen
#   on.
#
# @param port [Boolean] Specifies the port number SSHD listens on.
#
# @param macs [Array] Specifies the available MAC algorithms.
#
# @param permitemptypasswords [Boolean] When password authentication is allowed,
#   it specifies whether the server allows login to accounts with empty password
#   strings.
#
# @param permitrootlogin [Boolean] Specifies whether root can log in using SSH.
#
# @param printlastlog [Boolean] Specifies whether SSHD should print the date and
#   time of the last user login when a user logs in interactively.
#
# @param subsystem [String] Configures and external subsystem for file
#   transfers.
#
# @param usepam [Boolean] Enables the Pluggable Authentication Module interface.
#
# @param useprivilegeseparation [Boolean] Specifies whether sshd separates
#   privileges by creating an unprivileged child process to deal with incoming
#   network traffic.
#
# @param x11forwarding [Boolean] Specifies whether X11 forwarding is permitted.
#
# @param client_nets [Array] The networks to allow to connect to SSH.
#
# @param use_iptables [Boolean] If true, use the SIMP iptables class.
#
# @param use_ldap [Boolean] If true, enable LDAP support on the system. If
#   authorizedkeyscommand is empty, this will set the authorizedkeyscommand to
#   ssh-ldap-wrapper so that SSH public keys can be stored directly in LDAP.
#
# @param use_tcpwrappers [Boolean] If true, allow sshd tcpwrapper.
#
# @param use_haveged [Boolean] If true, include the haveged module to assist
#   with entropy generation.
#
# @param use_sssd [Boolean] If true, use sssd.
#
# == Authors
#
# * Trevor Vaughan <mailto:tvaughan@onyxpoint.com>
#
class ssh::server::conf (
  $acceptenv = [
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
    'LC_ALL'
  ],
  $authorizedkeysfile = '/etc/ssh/local_keys/%u',
  $authorizedkeyscommand = '',
  $authorizedkeyscommanduser = 'nobody',
  $banner = '/etc/issue.net',
  $challengeresponseauthentication = false,
  $ciphers = $::ssh::server::params::ciphers,
  $fallback_ciphers = $::ssh::server::params::fallback_ciphers,
  $enable_fallback_ciphers = true,
  $compression = false,
  $syslogfacility = 'AUTHPRIV',
  $gssapiauthentication = false,
  $kex_algorithms = $::ssh::server::params::kex_algorithms,
  $listenaddress = '0.0.0.0',
  $port = '22',
  $macs = $::ssh::server::params::macs,
  $permitemptypasswords = false,
  $permitrootlogin = false,
  $printlastlog = false,
  $subsystem = 'sftp /usr/libexec/openssh/sftp-server',
  $usepam = true,
  $useprivilegeseparation = true,
  $x11forwarding = false,
  $client_nets = 'any',
  $use_iptables = defined('$::use_iptables') ? { true => getvar('::use_iptables'), default => hiera('use_iptables', true) },
  $use_ldap = defined('$::use_ldap') ? { true => getvar('::use_ldap'), default => hiera('use_ldap', true) },
  $use_sssd = $::ssh::server::params::use_sssd,
  $use_haveged = defined('$::use_haveged') ? { true => getvar('::use_haveged'), default => hiera('use_haveged', true) },
  $use_tcpwrappers = true
) inherits ::ssh::server::params {
  assert_private()

  if $use_ldap {
    if $use_sssd {
      $_use_ldap = false
    }
    else {
      $_use_ldap = $use_ldap
    }
  }
  else {
    $_use_ldap = $use_ldap
  }

  if !empty($authorizedkeyscommand) {
    if ( $::operatingsystem in ['RedHat','CentOS','Fedora'] )
      and ( versioncmp($::operatingsystemmajrelease,'6') > 0 )
    {
      if empty($authorizedkeyscommanduser) {
        fail('$authorizedkeyscommanduser must be set if $authorizedkeyscommand is set')
      }
    }

    validate_absolute_path($authorizedkeyscommand)
  }
  validate_array($acceptenv)
  validate_array($ciphers)
  validate_array($fallback_ciphers)
  validate_bool($enable_fallback_ciphers)
  if $compression != 'delayed' { validate_bool($compression) }
  validate_bool($challengeresponseauthentication)
  validate_bool($gssapiauthentication)
  validate_array($kex_algorithms)
  validate_bool($permitemptypasswords)
  validate_bool($permitrootlogin)
  validate_bool($printlastlog)
  validate_bool($usepam)
  validate_bool($useprivilegeseparation)
  validate_bool($x11forwarding)
  validate_port($port)
  validate_array($macs)
  validate_bool($use_iptables)
  validate_bool($use_ldap)
  validate_bool($use_sssd)
  validate_bool($use_tcpwrappers)
  validate_bool($use_haveged)


  if $enable_fallback_ciphers {
    $_ciphers = unique(flatten([$ciphers,$fallback_ciphers]))
  }
  else {
    $_ciphers = $ciphers
  }

  file { '/etc/ssh/sshd_config':
    owner  => 'root',
    group  => 'root',
    mode   => '0600',
    notify => Service['sshd'],
  }

  # set ALL THE THINGS
  if is_array($acceptenv) {
    $acceptenv_array = $acceptenv
  }
  else {
    $acceptenv_array = split($acceptenv, ' ')
  }

  sshd_config{ 'AcceptEnv': value => $acceptenv_array }
  sshd_config{ 'AuthorizedKeysFile': value => $authorizedkeysfile }
  sshd_config{ 'Banner': value => $banner }
  sshd_config{ 'ChallengeResponseAuthentication': value => ssh_config_bool_translate($challengeresponseauthentication) }
  sshd_config{ 'Ciphers': value => $_ciphers }
  sshd_config{ 'Compression': value => ssh_config_bool_translate($compression) }
  sshd_config{ 'SyslogFacility': value => $syslogfacility}
  sshd_config{ 'GSSAPIAuthentication': value => ssh_config_bool_translate($gssapiauthentication) }
  # Kex should be empty openssl < 5.7, they are not supported.
  if !empty($kex_algorithms) { sshd_config{ 'KexAlgorithms': value => $kex_algorithms } }
  sshd_config{ 'ListenAddress': value => $listenaddress }
  sshd_config{ 'Port': value => $port }
  sshd_config{ 'MACs': value => $macs }
  sshd_config{ 'PermitEmptyPasswords': value => ssh_config_bool_translate($permitemptypasswords) }
  sshd_config{ 'PermitRootLogin': value => ssh_config_bool_translate($permitrootlogin) }
  sshd_config{ 'PrintLastLog': value => ssh_config_bool_translate($printlastlog) }
  sshd_config{ 'UsePAM': value => ssh_config_bool_translate($usepam) }
  sshd_config{ 'UsePrivilegeSeparation': value => ssh_config_bool_translate($useprivilegeseparation) }
  sshd_config{ 'X11Forwarding': value => ssh_config_bool_translate($x11forwarding) }

  if !empty($authorizedkeyscommand) {
    sshd_config { 'AuthorizedKeysCommand': value => $authorizedkeyscommand }
    if ( $::operatingsystem in ['RedHat','CentOS','Fedora'] )
      and ( versioncmp($::operatingsystemmajrelease,'6') > 0 )
    {
      sshd_config { 'AuthorizedKeysCommandUser': value => $authorizedkeyscommanduser }
    }
  }
  elsif $use_sssd{
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

  if $use_iptables {
    include '::iptables'
    iptables::add_tcp_stateful_listen { 'allow_sshd':
      order       => '8',
      client_nets => $client_nets,
      dports      => $port
    }
  }

  if $use_tcpwrappers {
    include '::tcpwrappers'
    tcpwrappers::allow { 'sshd':
      pattern => nets2ddq($client_nets),
      order   => '1'
    }
  }

  if $use_haveged {
    include '::haveged'
  }
}
