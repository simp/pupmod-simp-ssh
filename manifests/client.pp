# == Class: ssh::client
#
# Sets up a ssh client and creates /etc/ssh/ssh_config.
#
# == Parameters
#
# [*add_default_entry*]
# Type: Boolean
# Default: true
#   Set this if you wish to automatically have the '*' Host entry set up with
#   some sane defaults.
#
# [*use_fips*]
# Type: Boolean
# Default: false
#   If set, adjust for FIPS mode. If FIPS is already enabled, this will be
#   ignored.
#
# [*use_haveged*]
# Type: Boolean
# Default: true
#   If true, include the haveged module to assist with entropy generation.
#
# == Authors
#
# * Trevor Vaughan <mailto:tvaughan@onyxpoint.com>
#
class ssh::client (
  $add_default_entry = true,
  $use_fips = defined('$::fips_enabled') ? { true => str2bool($::fips_enabled), default => hiera('use_fips', false) },
  $use_haveged = true
) {

  validate_bool($add_default_entry)
  validate_bool($use_haveged)

  compliance_map()

  if $add_default_entry {
    ssh::client::add_entry { '*': }
  }

  concat_build { 'ssh_config':
    order   => ['*.conf'],
    target  => '/etc/ssh/ssh_config',
    require => Package['openssh-clients']
  }

  file { '/etc/ssh/ssh_known_hosts':
    owner => 'root',
    group => 'root',
    mode  => '0644'
  }

  file { '/etc/ssh/ssh_config':
    owner     => 'root',
    group     => 'root',
    mode      => '0644',
    subscribe => Concat_build['ssh_config'],
    require   => Package['openssh-clients'],
    audit     => content
  }

  package { 'openssh-clients': ensure => 'latest' }

  if $use_haveged {
    include '::haveged'
  }
}
