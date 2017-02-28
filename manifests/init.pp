# Sets up files for ssh.
#
# @param enable_client  If true, set up the SSH client configuration files.
#
# @param enable_server  If true, set up an SSH server on the system.
#
# @author Trevor Vaughan <mailto:tvaughan@onyxpoint.com>
#
class ssh (
  Boolean $enable_client = true,
  Boolean $enable_server = true
){

  if $enable_client { include '::ssh::client' }
  if $enable_server { include '::ssh::server' }

  file { '/etc/ssh':
    owner => 'root',
    group => 'root',
    mode  => '0755'
  }
}
