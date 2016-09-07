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
# @param use_iptables [Boolean] If set, use the SIMP iptables module.
#
# @option name [String] The 'Host' entry name.
#
# @option address_family [String] The IP Address family to use when connecting.
#   Valid options: 'any', 'inet', 'inet6'.
#
# @param batchmode [Boolean] If set to true, passphrase/password querying will
#   be disabled. This option is useful in scripts and other batch jobs where no
#   user is present to supply the password.
#
# @param bindaddress [String] Use the specified address on the local machine as
#   the source address of the connection. Only useful on systems with more than
#   one address. Note that this option does not work if UsePrivilegedPort is set
#   to false.
#
# @param challengeresponseauthentication [Boolean] Specifies whether to use
#   challenge-response authentication.
#
# @param checkhostip [Boolean] If this flag is set to true, ssh will
#   additionally check the host IP address in the known_hosts file. This allows
#   ssh to detect if a host key changed due to DNS spoofing and will add
#   addresses of destination hosts to ~/.ssh/known_hosts in the process,
#   regardless of the setting of StrictHostKeyChecking.
#
# @param cipher [String] Specifies the cipher to use for encrypting the session
#   in protocol version 1. Valid Options: 'blowfish', '3des', 'des'.
#   '3des'
#
# @param ciphers [Array] Specifies the ciphers allowed for protocol version 2 in
#   order of preference.
#
# @param clearallforwardings [Boolean] pecifies that all local, remote, and
#   dynamic port forwardings specified in the configuration files or on the
#   command line be cleared.
#
# @param compression [Boolean] Specifies whether to use compression.
#
# @param compressionlevel [Integer] Specifies the compression level to use if
#   compression is enabled.
#
# @param connectionattempts [Integer] Specifies the number of tries (one per
#   second) to make before exiting.
#
# @param connecttimeout [Integer] pecifies the timeout (in seconds) used when
#   connecting to the SSH server, instead of using the default system TCP
#   timeout.
#
# @param controlmaster [Boolean] Enables the sharing of multiple sessions over a
#   single network connection.
#
# @param controlpath [String] Specify the path to the control socket used for
#   connection sharing as set by controlmaster.
#
# @param dynamicforward [String] Specifies that a TCP port on the local machine
#   be forwarded over the secure channel, and the application protocol is then
#   used to determine where to connect to from the remote machine.
#
# @param enablesshkeysign [Boolean] Setting this option to true enables the use
#   of the helper program ssh-keysign during HostbasedAuthentication.
#
# @param escapechar [String] Sets the default escape character.
#
# @param exitonforwardfailure [Boolean] pecifies whether ssh should terminate
#   the connection if it cannot set up all requested dynamic, tunnel, local, and
#   remote port forwardings.
#
# @param forwardagent [Boolean] Specifies whether the connection to the
#   authentication agent (if any) will be forwarded to the remote machine.
#
# @param forwardx11 [Boolean] Specifies whether X11 connections will be
#   automatically redirected over the secure channel and DISPLAY set.
#
# @param forwardx11trusted [Boolean] If set to true, remote X11 clients will
#   have full access to the original X11 display.
#
# @param gatewayports [Boolean] Specifies whether remote hosts are allowed to
#   connect to local forwarded ports.
#
# @param globalknownhostsfile [String] Specifies one or more files to use for
#   the global host key database, separated by whitespace.
#
# @param gssapiauthentication [Boolean] pecifies whether user authentication
#   based on GSSAPI is allowed.
#
# @param gssapidelegatecredentials [Boolean] Forward credentials to the server.
#
# @param gssapikeyexchange [Boolean] Specifies whether key exchange based on
# GSSAPI may be used.
#
# @param gssapirenewalforcesrekey [Boolean] If set to true then renewal of
# the client's GSSAPI credentials will force the rekeying of the ssh connection.
#
# @param gssapitrustdns [Boolean] Set to true to indicate that the DNS is
# trusted to securely canonicalize the name of the host being connected to.
#
# @param hashknownhosts [Boolean] Indicates that SSH should hash host names and
#   addresses when they are added to known hosts.
#
# @param hostbasedauthentication [Boolean]: Specifies whether to try rhosts
#   based authentication with public key authentication.
#
# @param hostkeyalgorithms [String] Specifies the host key algorithms that the
#   client wants to use in order of preference.
#
# @param hostkeyalias [String] Specifies an alias that should be used instead of
#   the real host name when looking up or saving the host key in the host key
#   database files.
#
# @param hostname [String] Specifies the real hostname to log into.
#
# @param identitiesonly [Boolean] Specifies that ssh should only use the
#   authentication identity and certificate files explicitly configured in the
#   ssh_config files or passed on the ssh command-line, even if ssh-agent or
#   a PKCS11Provider offers more identities.
#
# @param identityfile [String] Specifies a file from which the user's DSA,
#   ECDSA, Ed25519 or RSA authentication identity is read.
#
# @param kbdinteractiveauthentication [Boolean] Specifies whether to use
#   keyboard-interactive authentication.
#
# @param kbdinteractivedevices [String] Specifies the list of methods to use in
#   keyboard-interactive authentication. Multiple method names must be
#   comma-separated.
#
# @param localcommand [String] Specifies a command to execute on the local
#   machine after successfully connecting to the server.
#
# @param localforward [String] Specifies that a TCP port on the local machine be
#   forwarded over the secure channel to the specified host and port from the
#   remote machine. The first argument must be [bind_address:]port and the
#   second argument must be host:hostport.
#
# @param macs [Array] Specifies the MAC (message authentication code) algorithms
#   in order of preference.
#
# @param ssh_loglevel [String] Gives the verbosity level that is used when
#   logging messages. Valid options: 'QUIET', 'FATAL', 'ERROR', 'INFO',
#   'VERBOSE', 'DEBUG', 'DEBUG1', 'DEBUG2', and 'DEBUG3'.
#
# @param nohostauthenticationforlocalhost [Boolean] This option can be used if
#   the home directory is shared across machines. In this case localhost will
#   refer to a different machine on each of the machines and the user will get
#   many warnings about changed host keys. However, this option disables host
#   authentication for localhost.
#
# @param numberofpasswordprompts [Integer] Specifies the number of password
#   prompts before giving up.
#
# @param passwordauthentication [Boolean] Specifies whether to use password
#   authentication.
#
# @param permitlocalcommand [Boolean] Allow local command execution via the
#   LocalCommand option or using the !command escape sequence.
#
# @param port [Port] Specifies the port number to connect on the remote host.
#
# @param preferredauthentications [Array] Specifies the order in which the
#   client should try authentication methods. The order will be determined from
#   the start of the array to the end of the array. Default:
#   ['publickey','hostbased','keyboard-interactive','password']
#
# @param protocol [String] Specifies the protocol version SSH should support in
#   order of preference.
#
# @param proxycommand [String] Specifies the command to use to connect to the
#   server.
#
# @param pubkeyauthentication [Boolean] Specifies whether to try public key
#   authentication.
#
# @param rekeylimit [String] Specifies the maximum amount of data that may be
#   transmitted before the session key is renegotiated, optionally followed a
#   maximum amount of time that may pass before the session key is renegotiated.
#
# @param remoteforward [String] Specifies that a TCP port on the remote machine
#   be forwarded over the secure channel to the specified host and port from the
#   local machine.
#
# @param rhostsrsaauthentication [Boolean] Specifies whether to try rhosts based
#   authentication with RSA host authentication.
#
# @param rsaauthentication [Boolean] Specifies whether to try RSA
#   Authentication.
#
# @param sendenv [Array] Specifies what variables from the local environ
#   should be sent to the server.
#
# @param serveralivecountmax [Integer] Sets the number of server alive messages
#   (see below) which may be sent without ssh receiving any messages back from
#   the server.
#
# @param serveraliveinterval [Integer] Sets a timeout interval in seconds after
#   which if no data has been received from the server. The default is 0,
#   indicating that these messages will not be sent to the server.
#
# @param smartcarddevice [String] Specifies which smartcard device to use.
#
#
# @param stricthostkeychecking [String] If set to yes, ssh will never
#   automatically add host keys to the known_hosts file, and refuses to connect
#   to hosts whose keys have changed.  If this flag is set to “ask”, new host
#   keys will be added to the user known host files only after the user has
#   confirmed that is what they really want to do, and ssh will refuse to
#   connect to hosts whose host key has changed. Valid Options: 'yes', 'no',
#   'ask'
#
# @param tcpkeepalive [Boolean] Specifies whether the system should send TCP
#   keepalive messages to the other side.
#
# @param tunnel [String] Request device forwarding between the client and
#   server.
#
# @param tunneldevice [String] Specifies the devices to open on the client and
#   the server.
#
# @param useprivilegedport [Boolean] Specifies whether to use a privileged port
#   for outgoing connections.
#
# @param user [String] Specifies the user to log in as.
#
# @param userknownhostsfile [String] Specifies one or more files to use for the
#   user host key database, seperated by whitespace.
#
# @param verifyhostkeydns [Boolean] Specifies whether to verify the remote key
#   using DNS and SSHFP resource records.
#
# @param visualhostkey [Boolean] If this flag is set to true, an ASCII art
#   representation of the remote host key fingerprint is printed in addition to
#   the fingerprint string at login and for unknown host keys.
#
# @param xauthlocation [String] Specifies the full pathname of the xauth
#   program.
#
# == Authors
#
# * Trevor Vaughan <mailto:tvaughan@onyxpoint.com>
#
define ssh::client::add_entry (
  $address_family = 'any',
  $batchmode = false,
  $bindaddress = '',
  $challengeresponseauthentication = true,
  $checkhostip = true,
  $cipher = '3des',
  $ciphers = [],
  $clearallforwardings = false,
  $compression = true,
  $compressionlevel = '6',
  $connectionattempts = '1',
  $connecttimeout = '0',
  $controlmaster = false,
  $controlpath = '',
  $dynamicforward = '',
  $enablesshkeysign = false,
  $escapechar = '~',
  $exitonforwardfailure = false,
  $forwardagent = false,
  $forwardx11 = false,
  $forwardx11trusted = false,
  $gatewayports = false,
  $globalknownhostsfile = '',
  $gssapiauthentication = false,
  $gssapikeyexchange = false,
  $gssapidelegatecredentials = false,
  $gssapirenewalforcesrekey = false,
  $gssapitrustdns = false,
  $hashknownhosts = true,
  $hostbasedauthentication = false,
  $hostkeyalgorithms = 'ssh-rsa,ssh-dss',
  $hostkeyalias = '',
  $hostname = '',
  $identitiesonly = false,
  $identityfile = '',
  $kbdinteractiveauthentication = true,
  $kbdinteractivedevices = '',
  $localcommand = '',
  $localforward = '',
  $macs = [],
  $ssh_loglevel = 'INFO',
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
  $proxycommand = '',
  $pubkeyauthentication = true,
  $rekeylimit = '',
  $remoteforward = '',
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
  $smartcarddevice = '',
  $stricthostkeychecking = 'ask',
  $tcpkeepalive = true,
  $tunnel = 'yes',
  $tunneldevice = '',
  $useprivilegedport = false,
  $user = '',
  $userknownhostsfile = '',
  $verifyhostkeydns = false,
  $visualhostkey = false,
  $xauthlocation = '/usr/bin/xauth'
) {
  include '::ssh::client::params'
  include '::ssh::client'

  if !empty($macs) {
    $_macs = $macs
  }
  else {
    $_macs = $::ssh::client::params::macs
  }
  if !empty($ciphers) {
    $_ciphers = $ciphers
  }
  else {
    $_ciphers = $::ssh::client::params::ciphers
  }

  $_name = ssh_format_host_entry_for_sorting($name)

  if $::ssh::client::use_fips {
    $_protocol = '2'
    $_cipher = ''
  }
  else {
    $_protocol = $protocol
    $_protocol_array = split($_protocol,',')

    if !('1' in $_protocol_array) {
      $_cipher = ''
    }
    else {
      $_cipher = $cipher
    }
  }

  validate_absolute_path($xauthlocation)
  validate_array($_ciphers)
  validate_array($_macs)
  validate_array($sendenv)
  validate_array($preferredauthentications)
  validate_array_member($address_family, ['any','inet','inet6'])
  unless empty($_cipher) { validate_array_member($_cipher, ['blowfish','3des','des']) }
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
  validate_between($compressionlevel, '1', '9')
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
  validate_bool($permitlocalcommand)
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
  validate_array_member($_protocol,['1','2','1,2','2,1'])

  $_use_fips = defined('$::fips_enabled') ? { true => str2bool($::fips_enabled), default => hiera('use_fips', false) }

  concat_fragment { "ssh_config+${_name}.conf":
    content => template('ssh/ssh_config.erb')
  }

}
