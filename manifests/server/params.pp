# == Class: ssh::server::params
#
# Default parameters for the SSH Server
#
# KexAlgorithm configuration was not added until 5.7
# Curve exchange was not fully supported until 6.5
#
# == Authors
#
# * Trevor Vaughan <mailto:tvaughan@onyxpoint.com>
#
class ssh::server::params {

  ## Public Variables ##

  # These should work with *everything*
  $fallback_ciphers = [
    'aes256-cbc',
    'aes192-cbc',
    'aes128-cbc'
  ]

  ## Private Variables ##

  # These are all that are supported on RHEL6
  $_fallback_kex_algorithms = [ 'diffie-hellman-group-exchange-sha256' ]
  $_fallback_macs = [ 'hmac-sha1' ]
  $_primary_ciphers = [
    'aes256-gcm@openssh.com',
    'aes128-gcm@openssh.com'
  ]

  if $::fips_enabled {
    if $::operatingsystem in ['RedHat','CentOS'] and versioncmp($::operatingsystemmajrelease,'7') >= 0 {

      if versioncmp($::openssh_version, '5.7') >= 0 {
        $kex_algorithms = [
          'ecdh-sha2-nistp521',
          'ecdh-sha2-nistp384',
          'ecdh-sha2-nistp256',
          'diffie-hellman-group-exchange-sha256'
        ]
      }
      $macs = [
        'hmac-sha2-256',
        'hmac-sha1'
      ]
      $ciphers = $_primary_ciphers
    }
    else {
      # Don't know what OS this is so fall back to whatever should work with
      # FIPS 140-2 in all cases.
      if versioncmp($::openssh_version, '5.7') >= 0 {
        $kex_algorithms = $_fallback_kex_algorithms
      }
      $macs = $_fallback_macs
      $ciphers = $fallback_ciphers
    }
  }
  else {
    if $::operatingsystem in ['RedHat','CentOS'] and versioncmp($::operatingsystemmajrelease,'7') >= 0 {
      # FIPS mode not enabled, stay within the bounds but expand the options

      if versioncmp($::openssh_version, '5.7') >= 0 {
        $base_kex_algorithms = [
          'ecdh-sha2-nistp521',
          'ecdh-sha2-nistp384',
          'ecdh-sha2-nistp256',
          'diffie-hellman-group-exchange-sha256'
        ]
        if versioncmp($::openssh_version, '6.5') >= 0 {
          $additional_kex_algorithms = ['curve25519-sha256@libssh.org']
        }
        else {
          $additional_kex_algorithms = []
        }
        $kex_algorithms = concat($additional_kex_algorithms,$base_kex_algorithms)
      }
      $macs = [
        'hmac-sha2-512-etm@openssh.com',
        'hmac-sha2-256-etm@openssh.com',
        'hmac-sha2-512',
        'hmac-sha2-256'
      ]
      $ciphers = $_primary_ciphers
    }
    else {
      # Don't know what OS this is so fall back to whatever should work with
      # FIPS 140-2 in all cases.
      if versioncmp($::openssh_version, '5.7') >= 0 {
        $kex_algorithms = $_fallback_kex_algorithms
      }
      $macs = $_fallback_macs
      $ciphers = $fallback_ciphers
    }
  }

  # This should be removed once we move over to SSSD for everything.
  if $::operatingsystem in ['RedHat','CentOS'] {
    if (versioncmp($::operatingsystemrelease,'6.7') < 0) {
      $_use_sssd = false
    }
    else {
      $_use_sssd = true
    }

    $use_sssd = defined('$::use_sssd') ? {
      true => $::use_sssd,
      default => hiera('use_sssd',$_use_sssd)
    }
  }
  else {
    fail("${::operatingsystem} not yet supported by ${module_name}")
  }
}
