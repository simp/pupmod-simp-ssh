# @summary Sets up a ssh server and starts sshd.
#
# A bare `include ssh` (or `include ssh::server`) installs the
# `openssh-server` package and does *nothing else*.  The `sshd` service,
# the `sshd` user/group, the `/var/empty/sshd` chroot scaffolding and the
# host-key file management are only declared when service management is
# requested via `$service_ensure`/`$service_enable`.  Activate the bundled
# `simp:defaults` compliance_engine profile (or set these parameters) to
# restore the pre-8.0.0 behavior.
#
# @param server_ensure The ensure status of the openssh-server package
#
# @param ldap_ensure The ensure status of the openssh-ldap package
#
# @param service_ensure
#   The `ensure` status of the `sshd` service.  Leave `undef` (the default)
#   to leave the service unmanaged.  Setting either this or `$service_enable`
#   causes the service (and its supporting resources) to be managed.
#
# @param service_enable
#   The `enable` status of the `sshd` service.  Leave `undef` (the default)
#   to leave the service unmanaged.
#
# @author https://github.com/simp/pupmod-simp-ssh/graphs/contributors
#
class ssh::server (
  String                            $server_ensure  = 'installed',
  String                            $ldap_ensure    = 'installed',
  Optional[Stdlib::Ensure::Service] $service_ensure = undef,
  Optional[Boolean]                 $service_enable = undef,
) {
  simplib::assert_metadata( $module_name )

  include 'ssh'
  include 'ssh::server::conf'

  # Service management (and everything that only matters when sshd actually
  # runs) is opt-in.  A bare include declares only the package.
  $_manage_service = ($service_ensure =~ NotUndef) or ($service_enable =~ NotUndef)

  package { 'openssh-server':
    ensure => $server_ensure
  }

  if $::ssh::server::conf::_use_ldap {
    package { 'openssh-ldap':
      ensure => $ldap_ensure
    }
  }

  if $_manage_service {
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
      source  => "file://${facts['timezone_file']}",
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
      ensure     => $service_ensure,
      enable     => $service_enable,
      hasstatus  => true,
      hasrestart => true,
      require    => [
        Package['openssh-server'],
        User['sshd']
      ],
      subscribe  => Class['ssh::server::conf']
    }

    # Make sure all ssh keys are managed for permissions per compliance settings.
    # The `ssh_host_keys` fact is undef on a node without sshd installed; guard
    # the iterator so the catalog still compiles (noop-safety).
    $_ssh_host_keys = $facts['ssh_host_keys'] ? {
      undef   => [],
      default => $facts['ssh_host_keys'],
    }
    $_ssh_host_keys.each |$key| {
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
}
