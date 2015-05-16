# == Define: ssh::client::add_entry
#
# Adds an entry to ssh_config
#
# == Examples
#
#   ssh::client::add_entry { '*':
#     gssapiauthentication => 'yes',
#     forwardx11trusted => 'yes'
#   }
#
# == Parameters
#
# See ssh_config(5) for descriptions
#
# [*name*]
# Type: String
# Default: '*'
#   The 'Host' entry name.
#
# [*address_family*]
# [*batchmode*]
# [*bindaddress*]
# [*challengeresponseauthentication*]
# [*checkhostip*]
# [*cipher*]
# [*ciphers*]
# [*clearallforwardings*]
# [*compression*]
# [*compressionlevel*]
# [*connectionattempts*]
# [*connecttimeout*]
# [*controlmaster*]
# [*controlpath*]
# [*dynamicforward*]
# [*enablesshkeysign*]
# [*escapechar*]
# [*exitonforwardfailure*]
# [*forwardagent*]
# [*forwardx11*]
# [*forwardx11trusted*]
# [*gatewayports*]
# [*globalknownhostsfile*]
# [*gssapiauthentication*]
# [*gssapidelegatecredentials*]
# [*gssapirenewalforcesrekey*]
# [*hashknownhosts*]
# [*hostbasedauthentication*]
# [*hostkeyalgorithms*]
# [*hostkeyalias*]
# [*hostname*]
# [*identitiesonly*]
# [*identityfile*]
# [*kbdinteractiveauthentication*]
# [*kbdinteractivedevices*]
# [*localcommand*]
# [*localforward*]
# [*ssh_loglevel*]
# [*macs*]
# [*nohostauthenticationforlocalhost*]
# [*numberofpasswordprompts*]
# [*passwordauthentication*]
# [*permitlocalcommand*]
# [*port*]
# [*preferredauthentications*]
# [*protocol*]
# [*proxycommand*]
# [*pubkeyauthentication*]
# [*rekeylimit*]
# [*remoteforward*]
# [*rhostsrsaauthentication*]
# [*rsaauthentication*]
# [*sendenv*]
# [*serveralivecountmax*]
# [*serveraliveinterval*]
# [*smartcarddevice*]
# [*stricthostkeychecking*]
# [*tcpkeepalive*]
# [*tunnel*]
# [*tunneldevice*]
# [*useprivilegedport*]
# [*user*]
# [*userknownhostsfile*]
# [*verifyhostkeydns*]
# [*visualhostkey*]
# [*xauthlocation*]
#
# == Authors
#
# * Trevor Vaughan <mailto:tvaughan@onyxpoint.com>
#
define ssh::client::add_entry (
  $address_family = 'any',
  $batchmode = false,
  $bindaddress = 'nil',
  $challengeresponseauthentication = true,
  $checkhostip = true,
  $cipher = '3des',
  $ciphers = [
    'aes256-ctr',
    'aes192-ctr',
    'aes128-ctr',
    'aes256-cbc',
    'aes192-cbc',
    'aes128-cbc',
    '3des-cbc'
  ],
  $clearallforwardings = false,
  $compression = true,
  $compressionlevel = '6',
  $connectionattempts = '1',
  $connecttimeout = '0',
  $controlmaster = false,
  $controlpath = 'nil',
  $dynamicforward = 'nil',
  $enablesshkeysign = false,
  $escapechar = '~',
  $exitonforwardfailure = false,
  $forwardagent = false,
  $forwardx11 = false,
  $forwardx11trusted = false,
  $gatewayports = false,
  $globalknownhostsfile = 'nil',
  $gssapiauthentication = false,
  $gssapikeyexchange = false,
  $gssapidelegatecredentials = false,
  $gssapirenewalforcesrekey = false,
  $gssapitrustdns = false,
  $hashknownhosts = true,
  $hostbasedauthentication = false,
  $hostkeyalgorithms = 'ssh-rsa,ssh-dss',
  $hostkeyalias = 'nil',
  $hostname = 'nil',
  $identitiesonly = false,
  $identityfile = 'nil',
  $kbdinteractiveauthentication = true,
  $kbdinteractivedevices = 'nil',
  $localcommand = 'nil',
  $localforward = 'nil',
  $ssh_loglevel = 'INFO',
  $macs = [
    'hmac-sha1',
  ],
  $nohostauthenticationforlocalhost = false,
  $numberofpasswordprompts = '3',
  $passwordauthentication = true,
  $permitlocalcommand = false,
  $port = '22',
  $preferredauthentications = [
    'publickey',
    'hostbased',
    'keyboard-interactive',
    'password'
  ],
  $protocol = '2',
  $proxycommand = 'nil',
  $pubkeyauthentication = true,
  $rekeylimit = 'nil',
  $remoteforward = 'nil',
  $rhostsrsaauthentication = false,
  $rsaauthentication = true,
  $sendenv = [
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
  ],
  $serveralivecountmax = '3',
  $serveraliveinterval = '0',
  $smartcarddevice = 'nil',
  $stricthostkeychecking = 'ask',
  $tcpkeepalive = true,
  $tunnel = 'yes',
  $tunneldevice = 'nil',
  $useprivilegedport = false,
  $user = 'nil',
  $userknownhostsfile = 'nil',
  $verifyhostkeydns = false,
  $visualhostkey = false,
  $xauthlocation = '/usr/bin/xauth'
) {
  include 'ssh::client'

  $l_name = ssh_format_host_entry_for_sorting($name)
  concat_fragment { "ssh_config+$l_name.conf":
    content => template('ssh/ssh_config.erb')
  }

  validate_absolute_path($xauthlocation)
  validate_array($ciphers)
  validate_array($macs)
  validate_array($sendenv)
  validate_array($preferredauthentications)
  validate_array_member($address_family, ['any','inet','inet6'])
  validate_array_member($cipher, ['blowfish','3des','des'])
  validate_array_member($ssh_loglevel, [
    'QUIET',
    'FATAL',
    'ERROR',
    'INFO',
    'VERBOSE',
    'DEBUG',
    'DEBUG1',
    'DEBUG2',
    'DEBUG3'
  ])
  validate_array_member($stricthostkeychecking, ['yes','no','ask'])
  validate_array_member($tunnel, ['yes','no','point-to-point','ethernet'])
  validate_between($compressionlevel, 1, 9)
  validate_bool($batchmode)
  validate_bool($challengeresponseauthentication)
  validate_bool($checkhostip)
  validate_bool($clearallforwardings)
  validate_bool($compression)
  validate_bool($controlmaster)
  validate_bool($enablesshkeysign)
  validate_bool($exitonforwardfailure)
  validate_bool($forwardagent)
  validate_bool($forwardx11)
  validate_bool($forwardx11trusted)
  validate_bool($gatewayports)
  validate_bool($gssapiauthentication)
  validate_bool($gssapikeyexchange)
  validate_bool($gssapidelegatecredentials)
  validate_bool($gssapirenewalforcesrekey)
  validate_bool($gssapitrustdns)
  validate_bool($hashknownhosts)
  validate_bool($hostbasedauthentication)
  validate_bool($identitiesonly)
  validate_bool($kbdinteractiveauthentication)
  validate_bool($nohostauthenticationforlocalhost)
  validate_bool($passwordauthentication)
  validate_bool($pubkeyauthentication)
  validate_bool($rhostsrsaauthentication)
  validate_bool($rsaauthentication)
  validate_bool($tcpkeepalive)
  validate_bool($useprivilegedport)
  validate_bool($verifyhostkeydns)
  validate_bool($visualhostkey)
  validate_integer($connectionattempts)
  validate_integer($connecttimeout)
  validate_integer($numberofpasswordprompts)
  validate_integer($serveralivecountmax)
  validate_integer($serveraliveinterval)
  validate_port($port)
}
