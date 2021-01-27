# @summary Default parameters for the SSH client
#
# @author https://github.com/simp/pupmod-simp-ssh/graphs/contributors
#
class ssh::client::params {
  $_fallback_macs = [ 'hmac-sha1' ]
  $_fallback_ciphers = [
    'aes256-ctr',
    'aes192-ctr',
    'aes128-ctr'
  ]

  $fips_macs = [
    'hmac-sha2-256',
    'hmac-sha1'
  ]
  $fips_ciphers = [
    'aes256-ctr',
    'aes192-ctr',
    'aes128-ctr'
  ]

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

  # If the host is configured to use IPA, enable this setting
  if $facts['ipa'] {
    $gssapiauthentication = true
  }
  else {
    $gssapiauthentication = false
  }
}
