# @summary Sets up a ssh server and starts sshd.
#
# A bare `include ssh` (or `include ssh::server`) installs the
# `openssh-server` package and does *nothing else*.  The `sshd` service,
# the `sshd` user/group, the `/var/empty/sshd` chroot scaffolding and the
# host-key file management are only declared when service management is
# requested via `$service_ensure`/`$service_enable`.  Activate the bundled
# `simp:defaults` compliance_engine profile (or set these parameters) to
# restore the pre-9.0.0 behavior.
#
# The service resource is always titled `Service['sshd']`, whatever
# `$service_name` is, so other code can refer to it the same way on every OS.
# The `sshd` user/group and `/var/empty/sshd` are also subject to
# `$manage_privsep`.
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
# @param service_name
#   The name of the sshd systemd unit.  Set by module data: `sshd` on EL and
#   `ssh` on Debian-family systems, where `sshd.service` is only an alias
#   that systemd will not enable or disable.
#
#   * On Ubuntu 24.04, `ssh.service` is socket-activated by default: the
#     package enables `ssh.socket` and leaves `ssh.service` disabled, so
#     `service_enable: true` adds a boot-time start of `ssh.service` (still
#     fed by the socket).  A generator builds the socket's listen addresses
#     from `Port`/`ListenAddress` in `sshd_config` at `systemctl
#     daemon-reload`, so restarting the service does not apply a change to
#     either; run `systemctl daemon-reload && systemctl restart ssh.socket`,
#     or turn socket activation off (`systemctl disable --now ssh.socket`).
#
# @param manage_privsep
#   When the service is managed, also manage the `sshd` privilege-separation
#   user and group (UID/GID 74) and the `/var/empty/sshd` chroot.  These
#   match EL packaging.  Set to `false` by module data on Debian-family
#   systems, whose package creates its own `sshd` user (dynamic UID) and
#   uses `/run/sshd`, created by systemd.
#
# @author https://github.com/simp/pupmod-simp-ssh/graphs/contributors
#
class ssh::server (
  String                            $server_ensure  = 'installed',
  String                            $ldap_ensure    = 'installed',
  Optional[Stdlib::Ensure::Service] $service_ensure = undef,
  Optional[Boolean]                 $service_enable = undef,
  String[1]                         $service_name   = 'sshd',
  Boolean                           $manage_privsep = true,
) {
  simplib::assert_metadata( $module_name )

  # Service management (and everything that only matters when sshd actually
  # runs) is opt-in.  A bare include declares only the package.  Computed
  # before anything else is included so that every consumer (including
  # `ssh::server::sshd_config_entry`) reads a value that is already set.
  $_manage_service = ($service_ensure =~ NotUndef) or ($service_enable =~ NotUndef)

  include 'ssh'
  include 'ssh::server::conf'

  package { 'openssh-server':
    ensure => $server_ensure
  }

  if $ssh::server::conf::_use_ldap {
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

    # The EL privilege-separation user and chroot.  Debian-family packages
    # create their own `sshd` user and use /run/sshd (see `$manage_privsep`).
    if $manage_privsep {
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
    }

    $_service_require = $manage_privsep ? {
      true    => [Package['openssh-server'], User['sshd']],
      default => [Package['openssh-server']],
    }

    service { 'sshd':
      ensure     => $service_ensure,
      enable     => $service_enable,
      name       => $service_name,
      hasstatus  => true,
      hasrestart => true,
      require    => $_service_require,
      subscribe  => Class['ssh::server::conf']
    }

    # Make sure all ssh keys are managed for permissions per compliance settings.
    # The `ssh_host_keys` fact is undef on a node without sshd installed; guard
    # the iterator so the catalog still compiles (noop-safety).  It is also
    # empty on Debian-family systems while /run/sshd does not exist (`sshd -T`
    # refuses to run), e.g. on a socket-activated Ubuntu 24.04 host before
    # the first connection.
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
          notify    => [Exec['gensshpub'], Service['sshd']],
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
          require     => [Package['openssh-server'], File[$key]],
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
