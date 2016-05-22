# == Class: ssh::server
#
# Sets up a ssh server and starts sshd.
#
# == Parameters
#
# [*use_simp_pki*]
# Type: Boolean
# Default: true
#   If true, will include 'pki' and then use the certificates that are
#   transferred to generate the system SSH certificates for consistency.
#
# == Authors
#
# * Trevor Vaughan <mailto:tvaughan@onyxpoint.com>
#
class ssh::server (
  $use_simp_pki = defined('$::use_simp_pki') ? { true => $::use_simp_pki, default => hiera('use_simp_pki', true) }
){
  validate_bool($use_simp_pki)

  compliance_map()

  include '::ssh'
  include '::ssh::server::conf'

  # A hack to work around broken Augeas Lenses
  file { '/usr/share/augeas/lenses/sshd.aug':
    owner  => 'root',
    group  => 'root',
    mode   => '0640',
    source => "puppet:///modules/${module_name}/augeas_lenses/sshd.aug",
    before => Class['ssh::server::conf']
  }

  file { '/etc/ssh/moduli':
    owner => 'root',
    group => 'root',
    mode  => '0600'
  }

  file { '/etc/ssh/ssh_host_dsa_key':
    owner => 'root',
    group => 'root',
    mode  => '0600'
  }

  file { '/etc/ssh/ssh_host_dsa_key.pub':
    owner => 'root',
    group => 'root',
    mode  => '0644'
  }

  file { '/etc/ssh/ssh_host_key':
    owner => 'root',
    group => 'root',
    mode  => '0600'
  }

  file { '/etc/ssh/ssh_host_key.pub':
    owner => 'root',
    group => 'root',
    mode  => '0644'
  }

  file { '/var/empty/sshd':
    ensure  => 'directory',
    owner   => 'root',
    group   => 'root',
    mode    => '0744',
    require => Package['openssh-server'],
  }

  file { '/var/empty/sshd/etc':
    ensure  => 'directory',
    owner   => 'root',
    group   => 'root',
    mode    => '0755',
    require => Package['openssh-server']
  }

  file { '/var/empty/sshd/etc/localtime':
    source  => '/etc/localtime',
    force   => true,
    require => Package['openssh-server']
  }

  group { 'sshd':
    ensure    => 'present',
    allowdupe => false,
    gid       => '74'
  }

  package { 'openssh-server': ensure => 'latest' }

  if $::ssh::server::conf::_use_ldap {
    package { 'openssh-ldap': ensure => 'latest' }
  }

  user { 'sshd':
    ensure     => 'present',
    allowdupe  => false,
    comment    => 'Privilege-separated SSH',
    gid        => '74',
    home       => '/var/empty/sshd',
    membership => 'inclusive',
    shell      => '/sbin/nologin',
    uid        => '74'
  }

  service { 'sshd':
    ensure     => 'running',
    enable     => true,
    hasstatus  => true,
    hasrestart => true,
    require    => Package['openssh-server'],
    subscribe  => Class['::ssh::server::conf']
  }

  if to_string($::ssh::server::conf::port) != '22' and defined('$::selinux_enforced') and str2bool(getvar('::selinux_enforced')) {
    # This should really be a custom type...
    exec { "SELinux Allow SSH Port ${::ssh::server::conf::port}":
      command => "semanage port -a -t ssh_port_t -p tcp ${::ssh::server::conf::port}",
      unless  => "semanage port -C -l | grep -qe 'ssh_port_t[[:space:]]*tcp[[:space:]]*${::ssh::server::conf::port}'",
      path    => [
        '/usr/local/sbin',
        '/usr/local/bin',
        '/usr/sbin',
        '/usr/bin'
      ],
      notify  => Service['sshd']
    }
  }

  if $use_simp_pki {
    include '::pki'

    file { '/etc/ssh/ssh_host_rsa_key':
      owner     => 'root',
      group     => 'root',
      mode      => '0600',
      source    => "file:///etc/pki/private/${::fqdn}.pem",
      subscribe => File["/etc/pki/private/${::fqdn}.pem"],
      notify    => [ Exec['gensshpub'], Service['sshd'] ],
    }

    file { '/etc/ssh/ssh_host_rsa_key.pub':
      owner     => 'root',
      group     => 'root',
      mode      => '0644',
      subscribe => Exec['gensshpub'],
    }

    exec { 'gensshpub':
      command     => '/usr/bin/ssh-keygen -y -f /etc/ssh/ssh_host_rsa_key > /etc/ssh/ssh_host_rsa_key.pub',
      refreshonly => true,
      require     => Package['openssh-server']
    }
  }
  else {
    file { '/etc/ssh/ssh_host_rsa_key':
      owner => 'root',
      group => 'root',
      mode  => '0600'
    }

    file { '/etc/ssh/ssh_host_rsa_key.pub':
      owner => 'root',
      group => 'root',
      mode  => '0644'
    }
  }
}
