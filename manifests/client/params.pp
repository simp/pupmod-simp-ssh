# Default parameters for the SSH client
#
# @author Trevor Vaughan <mailto:tvaughan@onyxpoint.com>
#
class ssh::client::params {

  # These are all that are supported on RHEL6
  $_fallback_macs = [ 'hmac-sha1' ]
  $_fallback_ciphers = [
    'aes256-ctr',
    'aes192-ctr',
    'aes128-ctr'
  ]

  if $facts['os']['family'] == 'RedHat' and versioncmp($facts['os']['release']['major'],'7') >= 0 {
    $fips_macs = [
      'hmac-sha2-256',
      'hmac-sha1'
    ]
    $fips_ciphers = [
      'aes256-ctr',
      'aes192-ctr',
      'aes128-ctr'
    ]
  }
  else {
    # Don't know what OS this is so fall back to whatever should work with
    # FIPS 140-2 in all cases.

    $fips_macs = $_fallback_macs
    $fips_ciphers = $_fallback_ciphers
  }

  if $facts['os']['family'] == 'RedHat' and versioncmp($facts['os']['release']['major'],'7') >= 0 {
    # FIPS mode not enabled, stay within the bounds but expand the options
    $macs = [
      'hmac-sha2-512-etm@openssh.com',
      'hmac-sha2-256-etm@openssh.com',
      'hmac-sha2-512',
      'hmac-sha2-256'
    ]
    $ciphers = [
      'aes256-gcm@openssh.com',
      'aes128-gcm@openssh.com',
      'aes256-ctr',
      'aes192-ctr',
      'aes128-ctr'
    ]
  }
  else {
    # Don't know what OS this is so fall back to whatever should work with
    # FIPS 140-2 in all cases.

    $macs = $_fallback_macs
    $ciphers = $_fallback_ciphers
  }

  # If the host is configured to use IPA, enable this setting
  if $facts['ipa'] {
    $gssapiauthentication = true
  }
  else {
    $gssapiauthentication = false
  }
}
