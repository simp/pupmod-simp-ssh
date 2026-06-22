# @summary Sets up a ssh client and creates /etc/ssh/ssh_config.
#
# A bare `include ssh` (or `include ssh::client`) installs the
# `openssh-clients` package and does *nothing else*.  The default `Host *`
# entry in `/etc/ssh/ssh_config` (and management of `ssh_config`/
# `ssh_known_hosts`) is opt-in via `$add_default_entry`.  Activate the bundled
# `simp:defaults` compliance_engine profile (or set `$add_default_entry`) to
# restore the pre-8.0.0 behavior.
#
# @param add_default_entry Set this if you wish to automatically
#   have the '*' Host entry set up with some sane defaults.
#
# @param fips If set or FIPS is already enabled, adjust for FIPS mode.
#
# @param haveged If true, include the haveged module to assist with entropy generation.
#
# @param package_ensure The ensure status the openssh-clients package
#
# @author https://github.com/simp/pupmod-simp-ssh/graphs/contributors
#
class ssh::client (
  Boolean $add_default_entry = false,
  Boolean $haveged           = false,
  Boolean $fips              = false,
  String  $package_ensure    = 'installed',
) {
  simplib::assert_metadata( $module_name )

  package { 'openssh-clients':
    ensure => $package_ensure
  }

  if $add_default_entry {
    ssh::client::host_config_entry { '*': }

    file { '/etc/ssh/ssh_config':
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      require => Package['openssh-clients']
    }

    file { '/etc/ssh/ssh_known_hosts':
      owner => 'root',
      group => 'root',
      mode  => '0644'
    }
  }

  if $haveged {
    simplib::assert_optional_dependency($module_name, 'simp/haveged')

    include 'haveged'
  }
}
