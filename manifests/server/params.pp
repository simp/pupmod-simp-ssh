# @summary Default parameters for the SSH Server
#
# * ``KexAlgorithm`` configuration was not added until openssh 5.7
# * ``Curve`` exchange was not fully supported until openssh 6.5
#
# @author https://github.com/simp/pupmod-simp-ssh/graphs/contributors
#
class ssh::server::params {

  ## Public Variables ##
  $acceptenv = [
    'LANG',
    'LC_CTYPE',
    'LC_NUMERIC',
    'LC_TIME',
    'LC_COLLATE',
    'LC_MONETARY',
    'LC_MESSAGES',
    'LC_PAPER',
    'LC_NAME',
    'LC_ADDRESS',
    'LC_TELEPHONE',
    'LC_MEASUREMENT',
    'LC_IDENTIFICATION',
    'LC_ALL'
  ]

  # These should work with *everything*
  $fallback_ciphers = [
    'aes256-ctr',
    'aes192-ctr',
    'aes128-ctr'
  ]

  $ciphers = [
    'aes256-gcm@openssh.com',
    'aes128-gcm@openssh.com',
    'aes256-ctr',
    'aes192-ctr',
    'aes128-ctr'
  ]

  if versioncmp($facts['openssh_version'], '5.7') >= 0 {
    $fips_kex_algorithms = [
      'ecdh-sha2-nistp521',
      'ecdh-sha2-nistp384',
      'ecdh-sha2-nistp256',
      'diffie-hellman-group-exchange-sha256'
    ]
  }
  else {
    $fips_kex_algorithms = []
  }
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

  if versioncmp($facts['openssh_version'], '5.7') >= 0 {
    $base_kex_algorithms = [
      'ecdh-sha2-nistp521',
      'ecdh-sha2-nistp384',
      'ecdh-sha2-nistp256',
      'diffie-hellman-group-exchange-sha256'
    ]
    if versioncmp($facts['openssh_version'], '6.5') >= 0 {
      $additional_kex_algorithms = ['curve25519-sha256@libssh.org']
    }
    else {
      $additional_kex_algorithms = []
    }
    $kex_algorithms = concat($additional_kex_algorithms, $base_kex_algorithms)
  }
  else {
    $kex_algorithms = []
  }
  $macs = [
    'hmac-sha2-512-etm@openssh.com',
    'hmac-sha2-256-etm@openssh.com',
    'hmac-sha2-512',
    'hmac-sha2-256'
  ]

  # This setting is only present in old openssh versions
  if versioncmp($facts['openssh_version'], '7.4') >= 0 {
    $rhostsrsaauthentication = undef
  }
  else {
    $rhostsrsaauthentication = false
  }

  # If the host is configured to use IPA, enable this setting
  if $facts['ipa'] {
    $gssapiauthentication = true
  }
  else {
    $gssapiauthentication = false
  }
}
