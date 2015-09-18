# == Class: ssh::client::params
#
# Default parameters for the SSH client
#
# == Authors
#
# * Trevor Vaughan <mailto:tvaughan@onyxpoint.com>
#
class ssh::client::params {
  # These are all that are supported on RHEL6
  $_fallback_macs = [ 'hmac-sha1' ]
  $_fallback_ciphers = [
    'aes256-cbc',
    'aes192-cbc',
    'aes128-cbc'
  ]
  if $::fips_enabled {
    if $::operatingsystem in ['RedHat','CentOS'] and versioncmp($::operatingsystemmajrelease,'7') >= 0 {
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

      $macs = $_fallback_macs
      $ciphers = $_fallback_ciphers
    }
  }
  else {
    if $::operatingsystem in ['RedHat','CentOS'] and versioncmp($::operatingsystemmajrelease,'7') >= 0 {
      # FIPS mode not enabled, stay within the bounds but expand the options
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

      $macs = $_fallback_macs
      $ciphers = $_fallback_ciphers
    }
  }
}
