# @summary Sets up a ssh server and starts sshd.
#
# @param server_ensure The ensure status of the openssh-server package
#
# @param ldap_ensure The ensure status of the openssh-ldap package
#
# @author https://github.com/simp/pupmod-simp-ssh/graphs/contributors
#
class ssh::server (
  String $server_ensure = simplib::lookup('simp_options::package_ensure', { 'default_value' => 'installed' }),
  String $ldap_ensure = simplib::lookup('simp_options::package_ensure', { 'default_value' => 'installed' }),
) {
  simplib::assert_metadata( $module_name )

  include 'ssh'
  include 'ssh::server::conf'

  file { '/etc/ssh/moduli':
    owner => 'root',
    group => 'root',
    mode  => '0644'
  }

  file { '/var/empty/sshd':
    ensure  => 'directory',
    owner   => 'root',
    group   => 'root',
    mode    => '0711',
    require => Package['openssh-server'],
  }

  file { '/var/empty/sshd/etc':
    ensure  => 'directory',
    owner   => 'root',
    group   => 'root',
    mode    => '0711',
    require => Package['openssh-server']
  }

  file { '/var/empty/sshd/etc/localtime':
    source  => 'file:///etc/localtime',
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    links   => 'follow',
    require => Package['openssh-server']
  }

  group { 'sshd':
    ensure    => 'present',
    allowdupe => false,
    gid       => '74'
  }

  package { 'openssh-server':
    ensure => $server_ensure
  }

  if $::ssh::server::conf::_use_ldap {
    package { 'openssh-ldap':
      ensure => $ldap_ensure
    }
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
    require    => [
      Package['openssh-server'],
      User['sshd']
    ],
    subscribe  => Class['ssh::server::conf']
  }

  # Make sure all ssh keys are managed for permissions per compiance settings
  $facts['ssh_host_keys'].each |$key| {
    if ($key =~ /ssh_host_rsa_key/) and $ssh::server::conf::pki {
      file { $key:
        owner     => 'root',
        group     => 'root',
        mode      => '0600',
        source    => "file://${ssh::server::conf::app_pki_key}",
        subscribe => Pki::Copy['sshd'],
        notify    => [ Exec['gensshpub'], Service['sshd'] ],
      }

      file { "${key}.pub":
        owner     => 'root',
        group     => 'root',
        mode      => '0644',
        subscribe => Exec['gensshpub'],
      }

      exec { 'gensshpub':
        command     => "/usr/bin/ssh-keygen -y -f ${key} > ${key}.pub",
        refreshonly => true,
        require     => [ Package['openssh-server'], File[$key] ],
      }
    }
    else {
      file { $key:
        owner => 'root',
        group => 'root',
        mode  => '0600'
      }

      file { "${key}.pub":
        owner => 'root',
        group => 'root',
        mode  => '0644'
      }
    }
  }
}
