# == Class: ssh
#
# Sets up files for ssh.
#
# == Parameters
#
# [*enable_client*]
# Type: Boolean
# Default: true
#   If true, set up the SSH client configuration files.
#
# [*enable_server*]
# Type: Boolean
# Default: true
#   If true, set up an SSH server on the system.
#
# == Authors
#
# * Trevor Vaughan <mailto:tvaughan@onyxpoint.com>
#
class ssh (
  $enable_client = true,
  $enable_server = true
){
  validate_bool($enable_client)
  validate_bool($enable_server)

  if $enable_client { include 'ssh::client' }
  if $enable_server { include 'ssh::server' }

  file { '/etc/ssh':
    owner => 'root',
    group => 'root',
    mode  => '0755'
  }
}
