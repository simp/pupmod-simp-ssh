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
# == Authors
#
# * Trevor Vaughan <mailto:tvaughan@onyxpoint.com>
#
class ssh::client (
  $add_default_entry = true
){

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

  validate_bool($add_default_entry)
}
