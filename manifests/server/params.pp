# == Class: ssh::server::params
#
# Default parameters for the SSH Server
#
# == Authors
#
# * Trevor Vaughan <mailto:tvaughan@onyxpoint.com>
#
class ssh::server::params {
  # These are all that are supported on RHEL6
  $_fallback_kex_algorithms = [ 'diffie-hellman-group-exchange-sha256' ]
  $_fallback_macs = [ 'hmac-sha1' ]
  $_fallback_ciphers = [
    'aes256-cbc',
    'aes192-cbc',
    'aes128-cbc'
  ]
  if $::fips_enabled {
    if $::operatingsystem in ['RedHat','CentOS'] and versioncmp($::operatingsystemmajrelease,'7') >= 0 {
      $kex_algorithms = [
        'ecdh-sha2-nistp521',
        'ecdh-sha2-nistp384',
        'ecdh-sha2-nistp256',
        'diffie-hellman-group-exchange-sha256'
      ]
      $macs = [
        'hmac-sha2-256',
        'hmac-sha1'
      ]
      $ciphers = [
        'aes256-gcm@openssh.com',
        'aes128-gcm@openssh.com'
      ]
    }
    else {
      # Don't know what OS this is so fall back to whatever should work with
      # FIPS 140-2 in all cases.

      $kex_algorithms = $_fallback_kex_algorithms
      $macs = $_fallback_macs
      $ciphers = $_fallback_ciphers
    }
  }
  else {
    if $::operatingsystem in ['RedHat','CentOS'] and versioncmp($::operatingsystemmajrelease,'7') >= 0 {
      # FIPS mode not enabled, stay within the bounds but expand the options
      $kex_algorithms = [
        'curve25519-sha256@libssh.org',
        'ecdh-sha2-nistp521',
        'ecdh-sha2-nistp384',
        'ecdh-sha2-nistp256',
        'diffie-hellman-group-exchange-sha256'
      ]
      $macs = [
        'hmac-sha2-512-etm@openssh.com',
        'hmac-sha2-256-etm@openssh.com',
        'hmac-sha2-512',
        'hmac-sha2-256'
      ]
      $ciphers = [
        'aes256-gcm@openssh.com',
        'aes128-gcm@openssh.com'
      ]
    }
    else {
      # Don't know what OS this is so fall back to whatever should work with
      # FIPS 140-2 in all cases.

      $kex_algorithms = $_fallback_kex_algorithms
      $macs = $_fallback_macs
      $ciphers = $_fallback_ciphers
    }
  }
}
