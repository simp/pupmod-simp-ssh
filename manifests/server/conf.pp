# == Class: ssh::server::conf
#
# Sets up sshd_config and adds an iptables rule if iptables is being used.
#
# == Parameters
#   This variable can be set using Augeas in addition to this location
#   with no adverse effects.
#
# [*acceptenv*]
# [*authorizedkeysfile*]
# Type: String
# Default: /etc/ssh/local_keys/%u
#   This is set to a non-standard location to provide for increased control
#   over who can log in as a given user.
#
# [*authorizedkeyscommand*]
# [*authorizedkeyscommanduser*]
# [*banner*]
# [*challengeresponseauthentication*]
# [*compression*]
# [*ciphers*]
# [*syslogfacility*]
# [*gssapiauthentication*]
# [*listenaddress*]
# [*port*]
# [*macs*]
# [*permitrootlogin*]
# [*printlastlog*]
# [*subsystem*]
# [*usepam*]
# [*useprivilegeseparation*]
# [*x11forwarding*]
# [*client_nets*]
#   The networks to allow to connect to SSH. Defaults to 'any'
#
# [*use_iptables*]
# Type: Boolean
# Default: hiera('use_iptables',true)
#   If true, use the SIMP iptables class.
#
# [*use_ldap*]
# Type: Boolean
# Default: hiera('use_ldap',true)
#   If true, enable LDAP support on the system.
#   If authorizedkeyscommand is empty, this will set the authorizedkeyscommand
#   to ssh-ldap-wrapper so that SSH public keys can be stored directly in LDAP.
#
# [*use_tcpwrappers]
# Type: Boolean
# Default: true
#   If true, allow sshd tcpwrapper.
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
  $ciphers = [
    'aes256-cbc',
    'aes192-cbc',
    'aes128-cbc'
  ],
  $compression = false,
  $syslogfacility = 'AUTHPRIV',
  $gssapiauthentication = false,
  $listenaddress = '0.0.0.0',
  $port = '22',
  $macs = [
    'hmac-sha1'
  ],
  $permitrootlogin = false,
  $printlastlog = false,
  $subsystem = 'sftp /usr/libexec/openssh/sftp-server',
  $usepam = true,
  $useprivilegeseparation = true,
  $x11forwarding = false,
  $client_nets = 'any',
  $use_iptables = hiera('use_iptables',true),
  $use_ldap = hiera('use_ldap',true),
  $use_tcpwrappers = true
) {
  include 'ssh::server'

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
  sshd_config{ 'Ciphers': value => $ciphers }
  sshd_config{ 'Compression': value => ssh_config_bool_translate($compression) }
  sshd_config{ 'SyslogFacility': value => $syslogfacility}
  sshd_config{ 'GSSAPIAuthentication': value => ssh_config_bool_translate($gssapiauthentication) }
  sshd_config{ 'ListenAddress': value => $listenaddress }
  sshd_config{ 'Port': value => $port }
  sshd_config{ 'MACs': value => $macs }
  sshd_config{ 'PermitRootLogin': value => ssh_config_bool_translate($permitrootlogin) }
  sshd_config{ 'PrintLastLog': value => ssh_config_bool_translate($printlastlog) }
  sshd_config{ 'UsePAM': value => ssh_config_bool_translate($usepam) }
  sshd_config{ 'UsePrivilegeSeparation': value => ssh_config_bool_translate($useprivilegeseparation) }
  sshd_config{ 'X11Forwarding': value => ssh_config_bool_translate($x11forwarding) }

  if !empty($authorizedkeyscommand) {
    sshd_config { 'AuthorizedKeysCommand': value => $authorizedkeyscommand }
    if ( $::operatingsystem in ['RedHat','CentOS'] ) and ( $::lsbmajdistrelease > '6' ) {
      sshd_config { 'AuthorizedKeysCommandUser': value => $authorizedkeyscommanduser }
    }
  }
  elsif $use_ldap {
    sshd_config { 'AuthorizedKeysCommand': value => '/usr/libexec/openssh/ssh-ldap-wrapper' }
    if ( $::operatingsystem in ['RedHat','CentOS'] ) and ( $::lsbmajdistrelease > '6' ) {
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
    include 'iptables'
    iptables::add_tcp_stateful_listen { 'allow_sshd':
      order       => '8',
      client_nets => $client_nets,
      dports      => $port
    }
  }

  if $use_tcpwrappers {
    tcpwrappers::allow { 'sshd':
      pattern => nets2ddq($client_nets),
      order   => '1'
    }
  }

  if !empty($authorizedkeyscommand) {
    if ( $::operatingsystem in ['RedHat','CentOS'] ) and ( $::lsbmajdistrelease > '6' ) {
      if empty($authorizedkeyscommanduser) {
        fail('$authorizedkeyscommanduser must be set if $authorizedkeyscommand is set')
      }
    }

    validate_absolute_path($authorizedkeyscommand)
  }
  validate_array($acceptenv)
  validate_array($ciphers)
  if $compression != 'delayed' { validate_bool($compression) }
  validate_bool($challengeresponseauthentication)
  validate_bool($gssapiauthentication)
  validate_bool($permitrootlogin)
  validate_bool($printlastlog)
  validate_bool($usepam)
  validate_bool($useprivilegeseparation)
  validate_bool($x11forwarding)
  validate_port($port)
  validate_array($macs)
  validate_bool($use_iptables)
  validate_bool($use_ldap)
  validate_bool($use_tcpwrappers)
}
