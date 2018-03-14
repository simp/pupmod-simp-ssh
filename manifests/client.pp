# Sets up a ssh client and creates /etc/ssh/ssh_config.
#
# @param add_default_entry Set this if you wish to automatically
#   have the '*' Host entry set up with some sane defaults.
#
# @param fips If set or FIPS is already enabled, adjust for FIPS mode.
#
# @param haveged If true, include the haveged module to assist with entropy generation.
#
# @author Trevor Vaughan <mailto:tvaughan@onyxpoint.com>
#
class ssh::client (
  Boolean $add_default_entry = true,
  Boolean $haveged           = simplib::lookup('simp_options::haveged', { 'default_value' => false }),
  Boolean $fips              = simplib::lookup('simp_options::fips', { 'default_value' => false })
) {

  if $add_default_entry {
    ssh::client::host_config_entry { '*': }
  }

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

  package { 'openssh-clients': ensure => 'latest' }

  if $haveged {
    include '::haveged'
  }
}
