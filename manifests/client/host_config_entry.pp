# Creates a host entry to ssh_config
#
# @example Adding default entry
#
#   ssh::client::host_config_entry { '*':
#     gssapiauthentication => true,
#     forwardx11trusted    => true'
#   }
#
# @attr name The 'Host' entry name.
#
# @param address_family  The IP Address family to use when connecting.
#   Valid options: 'any', 'inet', 'inet6'.
#
# @param batchmode  If set to true, passphrase/password querying will
#   be disabled. This option is useful in scripts and other batch jobs where no
#   user is present to supply the password.
#
# @param bindaddress  Use the specified address on the local machine as
#   the source address of the connection. Only useful on systems with more than
#   one address. Note that this option does not work if UsePrivilegedPort is set
#   to false.
#
# @param challengeresponseauthentication  Specifies whether to use
#   challenge-response authentication.
#
# @param checkhostip  If this flag is set to true, ssh will
#   additionally check the host IP address in the known_hosts file. This allows
#   ssh to detect if a host key changed due to DNS spoofing and will add
#   addresses of destination hosts to ~/.ssh/known_hosts in the process,
#   regardless of the setting of StrictHostKeyChecking.
#
# @param cipher  Specifies the cipher to use for encrypting the session
#   in protocol version 1. Valid Options: 'blowfish', '3des', 'des'.
#
# @param ciphers Specifies the ciphers allowed for protocol version 2 in
#   order of preference. When unset, a strong set of ciphers is
#   automatically selected by this class, taking into account whether
#   the server is in FIPS mode.
#
# @param clearallforwardings  Specifies that all local, remote, and
#   dynamic port forwardings specified in the configuration files or on the
#   command line be cleared.
#
# @param compression  Specifies whether to use compression.
#
# @param compressionlevel  Specifies the compression level to use if
#   compression is enabled.
#
# @param connectionattempts  Specifies the number of tries (one per
#   second) to make before exiting.
#
# @param connecttimeout  Specifies the timeout (in seconds) used when
#   connecting to the SSH server, instead of using the default system TCP
#   timeout.
#
# @param controlmaster  Enables the sharing of multiple sessions over a
#   single network connection.
#
# @param controlpath  Specify the path to the control socket used for
#   connection sharing as set by controlmaster.
#
# @param dynamicforward  Specifies that a TCP port on the local machine
#   be forwarded over the secure channel, and the application protocol is then
#   used to determine where to connect to from the remote machine.
#
# @param enablesshkeysign  Setting this option to true enables the use
#   of the helper program ssh-keysign during HostbasedAuthentication.
#
# @param escapechar  Sets the default escape character. Must be a single character.
#
# @param exitonforwardfailure  Specifies whether ssh should terminate
#   the connection if it cannot set up all requested dynamic, tunnel, local, and
#   remote port forwardings.
#
# @param forwardagent  Specifies whether the connection to the
#   authentication agent (if any) will be forwarded to the remote machine.
#
# @param forwardx11  Specifies whether X11 connections will be
#   automatically redirected over the secure channel and DISPLAY set.
#
# @param forwardx11trusted  If set to true, remote X11 clients will
#   have full access to the original X11 display.
#
# @param gatewayports  Specifies whether remote hosts are allowed to
#   connect to local forwarded ports.
#
# @param globalknownhostsfile  Specifies one or more files to use for
#   the global host key database.
#
# @param gssapiauthentication  Specifies whether user authentication
#   based on GSSAPI is allowed. If the system is connected to an IPA domain,
#   this will be set to true, regardless of this parameter. It uses the
#   `ipa` fact to determine domain membership.
#
# @param gssapidelegatecredentials  Forward credentials to the server.
#
# @param gssapikeyexchange  Specifies whether key exchange based on
# GSSAPI may be used.
#
# @param gssapirenewalforcesrekey  If set to true then renewal of
# the client's GSSAPI credentials will force the rekeying of the ssh connection.
#
# @param gssapitrustdns  Set to true to indicate that the DNS is
# trusted to securely canonicalize the name of the host being connected to.
#
# @param hashknownhosts  Indicates that SSH should hash host names and
#   addresses when they are added to known hosts.
#
# @param hostbasedauthentication  Specifies whether to try rhosts
#   based authentication with public key authentication.
#
# @param hostkeyalgorithms  Specifies the host key algorithms that the
#   client wants to use in order of preference.
#
# @param hostkeyalias  Specifies an alias that should be used instead of
#   the real host name when looking up or saving the host key in the host key
#   database files.
#
# @param hostname  Specifies the real hostname to log into.
#
# @param identitiesonly  Specifies that ssh should only use the
#   authentication identity and certificate files explicitly configured in the
#   ssh_config files or passed on the ssh command-line, even if ssh-agent or
#   a PKCS11Provider offers more identities.
#
# @param identityfile  Specifies a file from which the user's DSA,
#   ECDSA, Ed25519 or RSA authentication identity is read.
#
# @param kbdinteractiveauthentication  Specifies whether to use
#   keyboard-interactive authentication.
#
# @param kbdinteractivedevices  Specifies the list of methods to use in
#   keyboard-interactive authentication. Multiple method names must be
#   comma-separated.
#
# @param localcommand  Specifies a command to execute on the local
#   machine after successfully connecting to the server.
#
# @param localforward  Specifies that a TCP port on the local machine be
#   forwarded over the secure channel to the specified host and port from the
#   remote machine. The first argument must be [bind_address:]port and the
#   second argument must be host:hostport.
#
# @param macs  Specifies the MAC (message authentication code) algorithms
#   in order of preference.  When unset, a strong set of algorithms is
#   automatically selected by this class, taking into account whether
#   the server is in FIPS mode.
#
# @param ssh_loglevel  Gives the verbosity level that is used when
#   logging messages. Valid options: 'QUIET', 'FATAL', 'ERROR', 'INFO',
#   'VERBOSE', 'DEBUG', 'DEBUG1', 'DEBUG2', and 'DEBUG3'.
#
# @param nohostauthenticationforlocalhost  This option can be used if
#   the home directory is shared across machines. In this case localhost will
#   refer to a different machine on each of the machines and the user will get
#   many warnings about changed host keys. However, this option disables host
#   authentication for localhost.
#
# @param numberofpasswordprompts  Specifies the number of password
#   prompts before giving up.
#
# @param passwordauthentication  Specifies whether to use password
#   authentication.
#
# @param permitlocalcommand  Allow local command execution via the
#   LocalCommand option or using the !command escape sequence.
#
# @param port  Specifies the port number to connect on the remote host.
#
# @param preferredauthentications  Specifies the order in which the
#   client should try authentication methods. The order will be determined from
#   the start of the array to the end of the array. Default:
#   ['publickey','hostbased','keyboard-interactive','password']
#
# @param protocol Specifies the protocol versions SSH should support.
#
# @param proxycommand  Specifies the command to use to connect to the
#   server.
#
# @param pubkeyauthentication  Specifies whether to try public key
#   authentication.
#
# @param rekeylimit  Specifies the maximum amount of data that may be
#   transmitted before the session key is renegotiated, optionally followed a
#   maximum amount of time that may pass before the session key is renegotiated.
#
# @param remoteforward  Specifies that a TCP port on the remote machine
#   be forwarded over the secure channel to the specified host and port from the
#   local machine.
#
# @param rhostsrsaauthentication  Specifies whether to try rhosts based
#   authentication with RSA host authentication.
#
# @param rsaauthentication  Specifies whether to try RSA Authentication.
#
# @param sendenv  Specifies what variables from the local environ
#   should be sent to the server.
#
# @param serveralivecountmax  Sets the number of server alive messages
#   (see below) which may be sent without ssh receiving any messages back from
#   the server.
#
# @param serveraliveinterval  Sets a timeout interval in seconds after
#   which if no data has been received from the server. The default is 0,
#   indicating that these messages will not be sent to the server.
#
# @param smartcarddevice  Specifies which smartcard device to use.
#
# @param stricthostkeychecking  If set to yes, ssh will never
#   automatically add host keys to the known_hosts file, and refuses to connect
#   to hosts whose keys have changed.  If this flag is set to "ask", new host
#   keys will be added to the user known host files only after the user has
#   confirmed that is what they really want to do, and ssh will refuse to
#   connect to hosts whose host key has changed. Valid Options: 'yes', 'no',
#   'ask'
#
# @param tcpkeepalive  Specifies whether the system should send TCP
#   keepalive messages to the other side.
#
# @param tunnel  If 'yes', request device forwarding between the client and
#   server.
#
# @param tunneldevice  Specifies the devices to open on the client and
#   the server.
#
# @param useprivilegedport  Specifies whether to use a privileged port
#   for outgoing connections.
#
# @param user  Specifies the user to log in as.
#
# @param userknownhostsfile  Specifies one or more files to use for the
#   user host key database, separated by whitespace.
#
# @param verifyhostkeydns  Specifies whether to verify the remote key
#   using DNS and SSHFP resource records.
#
# @param visualhostkey  If this flag is set to true, an ASCII art
#   representation of the remote host key fingerprint is printed in addition to
#   the fingerprint string at login and for unknown host keys.
#
# @param xauthlocation Specifies the full pathname of the xauth
#   program.
#
# @author Trevor Vaughan <mailto:tvaughan@onyxpoint.com>
#
define ssh::client::host_config_entry (
  Enum['any', 'inet', 'inet6']                          $address_family                   = 'any',
  Boolean                                               $batchmode                        = false,
  Optional[Simplib::Host]                               $bindaddress                      = undef,
  Boolean                                               $challengeresponseauthentication  = true,
  Boolean                                               $checkhostip                      = true,
  Enum['blowfish', '3des', 'des']                       $cipher                           = '3des',
  Optional[Array[String]]                               $ciphers                          = undef,
  Boolean                                               $clearallforwardings              = false,
  Boolean                                               $compression                      = true,
  Integer[1,9]                                          $compressionlevel                 = 6,
  Integer[1]                                            $connectionattempts               = 1,
  Integer[0]                                            $connecttimeout                   = 0,
  Enum['yes','no','ask']                                $controlmaster                    = 'no',
  Optional[Variant[Stdlib::Absolutepath, Enum['none']]] $controlpath                      = undef,
  Optional[Variant[Simplib::Port, Simplib::Host::Port]] $dynamicforward                   = undef,
  Boolean                                               $enablesshkeysign                 = false,
  Pattern[/^[[:graph:]]$/, /^\^[[:alpha:]]$/, /^none$/] $escapechar                       = '~',
  Boolean                                               $exitonforwardfailure             = false,
  Boolean                                               $forwardagent                     = false,
  Boolean                                               $forwardx11                       = false,
  Boolean                                               $forwardx11trusted                = false,
  Boolean                                               $gatewayports                     = false,
  Optional[Array[Stdlib::Absolutepath]]                 $globalknownhostsfile             = undef,
  Boolean                                               $gssapiauthentication             = false,
  Boolean                                               $gssapikeyexchange                = false,
  Boolean                                               $gssapidelegatecredentials        = false,
  Boolean                                               $gssapirenewalforcesrekey         = false,
  Boolean                                               $gssapitrustdns                   = false,
  Boolean                                               $hashknownhosts                   = true,
  Boolean                                               $hostbasedauthentication          = false,
  Array[String]                                         $hostkeyalgorithms                = ['ssh-rsa','ssh-dss'],
  Optional[String]                                      $hostkeyalias                     = undef,
  Optional[Simplib::Host]                               $hostname                         = undef,
  Boolean                                               $identitiesonly                   = false,
  Optional[String]                                      $identityfile                     = undef,
  Boolean                                               $kbdinteractiveauthentication     = true,
  Optional[Array[String]]                               $kbdinteractivedevices            = undef,
  Optional[String]                                      $localcommand                     = undef,
  Optional[String]                                      $localforward                     = undef,
  Optional[Array[String]]                               $macs                             = undef,
  Ssh::Sysloglevel                                      $ssh_loglevel                     = 'INFO',
  Boolean                                               $nohostauthenticationforlocalhost = false,
  Integer[1]                                            $numberofpasswordprompts          = 3,
  Boolean                                               $passwordauthentication           = true,
  Boolean                                               $permitlocalcommand               = false,
  Simplib::Port                                         $port                             = 22,
  Array[Ssh::Authentications]                           $preferredauthentications         = [ 'publickey',
                                                                                              'hostbased',
                                                                                              'keyboard-interactive',
                                                                                              'password' ],
  Variant[Integer[1,2], Enum['2,1']]                    $protocol                         = 2,
  Optional[String]                                      $proxycommand                     = undef,
  Boolean                                               $pubkeyauthentication             = true,
  Optional[String]                                      $rekeylimit                       = undef,
  Optional[String]                                      $remoteforward                    = undef,
  Boolean                                               $rhostsrsaauthentication          = false,
  Boolean                                               $rsaauthentication                = true,
  Array[String]                                         $sendenv                          = [ 'LANG',
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
                                                                                              'LC_ALL' ],
  Integer[1]                                            $serveralivecountmax              = 3,
  Integer[0]                                            $serveraliveinterval              = 0,
  Optional[String]                                      $smartcarddevice                  = undef,
  Enum['yes','no','ask']                                $stricthostkeychecking            = 'ask',
  Boolean                                               $tcpkeepalive                     = true,
  Enum['yes','no','point-to-point','ethernet']          $tunnel                           = 'yes',
  Optional[String]                                      $tunneldevice                     = undef,
  Boolean                                               $useprivilegedport                = false,
  Optional[String]                                      $user                             = undef,
  Optional[Array[Stdlib::Absolutepath]]                 $userknownhostsfile               = undef,
  Enum['yes','no','ask']                                $verifyhostkeydns                 = 'no',
  Boolean                                               $visualhostkey                    = false,
  Stdlib::Absolutepath                                  $xauthlocation                    = '/usr/bin/xauth'
) {
  include '::ssh::client::params'
  include '::ssh::client'

  if $macs and !empty($macs) {
    $_macs = $macs
  }
  else {
    if $::ssh::client::fips or $facts['fips_enabled'] {
      $_macs = $::ssh::client::params::fips_macs
    }
    else {
      $_macs = $::ssh::client::params::macs
    }
  }

  if $ciphers and !empty($ciphers) {
    $_ciphers = $ciphers
  }
  else {
    if $::ssh::client::fips or $facts['fips_enabled'] {
      $_ciphers = $::ssh::client::params::fips_ciphers
    }
    else {
      $_ciphers = $::ssh::client::params::ciphers
    }
  }

  if $::ssh::client::fips or $facts['fips_enabled'] {
    $_protocol = 2
    $_cipher = undef
  }
  elsif $protocol == 2 {
    $_protocol = $protocol
    $_cipher = undef
  }
  else {
    $_protocol = $protocol
    $_cipher = $cipher
  }

  # If the host is configured to use IPA, enable this setting
  if $gssapiauthentication or $::ssh::client::params::gssapiauthentication {
    $_gssapiauthentication = true
  }
  else {
    $_gssapiauthentication = false
  }

  $_name = ssh::format_host_entry_for_sorting($name)

  $target = '/etc/ssh/ssh_config'
  ssh_config{
    default:
      host   => $name,
      target => $target,
    ;
    "${_name}__AddressFamily":
      key   => 'AddressFamily',
      value => $address_family,
    ;
    "${_name}__Protocol":
      key   => 'Protocol',
      value => $_protocol,
    ;
    "${_name}__BatchMode":
      key   => 'BatchMode',
      value => ssh::config_bool_translate($batchmode),
    ;
    "${_name}__ChallengeResponseAuthentication":
      key   => 'ChallengeResponseAuthentication',
      value => ssh::config_bool_translate($challengeresponseauthentication),
    ;
    "${_name}__CheckHostIP":
      key   => 'CheckHostIP',
      value => ssh::config_bool_translate($checkhostip),
    ;
    "${_name}__Ciphers":
      key   => 'Ciphers',
      value => $_ciphers.join(','),
    ;
    "${_name}__ClearAllForwardings":
      key   => 'ClearAllForwardings',
      value => ssh::config_bool_translate($clearallforwardings),
    ;
    "${_name}__Compression":
      key   => 'Compression',
      value => ssh::config_bool_translate($compression),
    ;
    "${_name}__CompressionLevel":
      key   => 'CompressionLevel',
      value => $compressionlevel,
    ;
    "${_name}__ConnectionAttempts":
      key   => 'ConnectionAttempts',
      value => $connectionattempts,
    ;
    "${_name}__ConnectTimeout":
      key   => 'ConnectTimeout',
      value => $connecttimeout,
    ;
    "${_name}__ControlMaster":
      key   => 'ControlMaster',
      value => $controlmaster,
    ;
    "${_name}__EnableSSHKeysign":
      key   => 'EnableSSHKeysign',
      value => ssh::config_bool_translate($enablesshkeysign),
    ;
    "${_name}__EscapeChar":
      key   => 'EscapeChar',
      value => $escapechar,
    ;
    "${_name}__ExitOnForwardFailure":
      key   => 'ExitOnForwardFailure',
      value => ssh::config_bool_translate($exitonforwardfailure),
    ;
    "${_name}__ForwardAgent":
      key   => 'ForwardAgent',
      value => ssh::config_bool_translate($forwardagent),
    ;
    "${_name}__ForwardX11":
      key   => 'ForwardX11',
      value => ssh::config_bool_translate($forwardx11),
    ;
    "${_name}__ForwardX11Trusted":
      key   => 'ForwardX11Trusted',
      value => ssh::config_bool_translate($forwardx11trusted),
    ;
    "${_name}__GatewayPorts":
      key   => 'GatewayPorts',
      value => ssh::config_bool_translate($gatewayports),
    ;
    "${_name}__GSSAPIAuthentication":
      key   => 'GSSAPIAuthentication',
      value => ssh::config_bool_translate($_gssapiauthentication),
    ;
    "${_name}__GSSAPIKeyExchange":
      key   => 'GSSAPIKeyExchange',
      value => ssh::config_bool_translate($gssapikeyexchange),
    ;
    "${_name}__GSSAPIDelegateCredentials":
      key   => 'GSSAPIDelegateCredentials',
      value => ssh::config_bool_translate($gssapidelegatecredentials),
    ;
    "${_name}__GSSAPIRenewalForcesRekey":
      key   => 'GSSAPIRenewalForcesRekey',
      value => ssh::config_bool_translate($gssapirenewalforcesrekey),
    ;
    "${_name}__GSSAPITrustDns":
      key   => 'GSSAPITrustDns',
      value => ssh::config_bool_translate($gssapitrustdns),
    ;
    "${_name}__HashKnownHosts":
      key   => 'HashKnownHosts',
      value => ssh::config_bool_translate($hashknownhosts),
    ;
    "${_name}__HostbasedAuthentication":
      key   => 'HostbasedAuthentication',
      value => ssh::config_bool_translate($hostbasedauthentication),
    ;
    "${_name}__HostKeyAlgorithms":
      key   => 'HostKeyAlgorithms',
      value => $hostkeyalgorithms.join(','),
    ;
    "${_name}__IdentitiesOnly":
      key   => 'IdentitiesOnly',
      value => ssh::config_bool_translate($identitiesonly),
    ;
    "${_name}__KbdInteractiveAuthentication":
      key   => 'KbdInteractiveAuthentication',
      value => ssh::config_bool_translate($kbdinteractiveauthentication),
    ;
    "${_name}__LogLevel":
      key   => 'LogLevel',
      value => $ssh_loglevel,
    ;
    "${_name}__MACs":
      key   => 'MACs',
      value => $_macs.join(','),
    ;
    "${_name}__NoHostAuthenticationForLocalhost":
      key   => 'NoHostAuthenticationForLocalhost',
      value => ssh::config_bool_translate($nohostauthenticationforlocalhost),
    ;
    "${_name}__NumberOfPasswordPrompts":
      key   => 'NumberOfPasswordPrompts',
      value => $numberofpasswordprompts,
    ;
    "${_name}__PasswordAuthentication":
      key   => 'PasswordAuthentication',
      value => ssh::config_bool_translate($passwordauthentication),
    ;
    "${_name}__PermitLocalCommand":
      key   => 'PermitLocalCommand',
      value => ssh::config_bool_translate($permitlocalcommand),
    ;
    "${_name}__Port":
      key   => 'Port',
      value => $port,
    ;
    "${_name}__PreferredAuthentications":
      key   => 'PreferredAuthentications',
      value => $preferredauthentications.join(','),
    ;
    "${_name}__PubkeyAuthentication":
      key   => 'PubkeyAuthentication',
      value => ssh::config_bool_translate($pubkeyauthentication),
    ;
    "${_name}__RhostsRSAAuthentication":
      key   => 'RhostsRSAAuthentication',
      value => ssh::config_bool_translate($rhostsrsaauthentication),
    ;
    "${_name}__RSAAuthentication":
      key   => 'RSAAuthentication',
      value => ssh::config_bool_translate($rsaauthentication),
    ;
    "${_name}__SendEnv":
      key   => 'SendEnv',
      value => $sendenv.join(' '),
    ;
    "${_name}__ServerAliveCountMax":
      key   => 'ServerAliveCountMax',
      value => $serveralivecountmax,
    ;
    "${_name}__ServerAliveInterval":
      key   => 'ServerAliveInterval',
      value => $serveraliveinterval,
    ;
    "${_name}__StrictHostKeyChecking":
      key   => 'StrictHostKeyChecking',
      value => $stricthostkeychecking,
    ;
    "${_name}__TCPKeepAlive":
      key   => 'TCPKeepAlive',
      value => ssh::config_bool_translate($tcpkeepalive),
    ;
    "${_name}__Tunnel":
      key   => 'Tunnel',
      value => $tunnel,
    ;
    "${_name}__UsePrivilegedPort":
      key   => 'UsePrivilegedPort',
      value => ssh::config_bool_translate($useprivilegedport),
    ;
    "${_name}__VerifyHostKeyDNS":
      key   => 'VerifyHostKeyDNS',
      value => $verifyhostkeydns,
    ;
    "${_name}__VisualHostKey":
      key   => 'VisualHostKey',
      value => ssh::config_bool_translate($visualhostkey),
    ;
    "${_name}__XAuthLocation":
      key   => 'XAuthLocation',
      value => $xauthlocation,
    ;
  }

  if $_cipher {
    ssh_config{ "${_name}__Cipher":
      key    => 'Cipher',
      value  => $_cipher,
      host   => $name,
      target => $target,
    }
  }

  if $bindaddress {
    ssh_config{ "${_name}__BindAddress":
      key    => 'BindAddress',
      value  => $bindaddress,
      host   => $name,
      target => $target,
    }
  }

  if $controlpath {
    ssh_config{ "${_name}__ControlPath":
      key    => 'ControlPath',
      value  => $controlpath,
      host   => $name,
      target => $target,
    }
  }

  if $dynamicforward {
    ssh_config{ "${_name}__DynamicForward":
      key    => 'DynamicForward',
      value  => $dynamicforward,
      host   => $name,
      target => $target,
    }
  }

  if $globalknownhostsfile {
    ssh_config{ "${_name}__GlobalKnownHostsFile":
      key    => 'GlobalKnownHostsFile',
      value  => $globalknownhostsfile.join(' '),
      host   => $name,
      target => $target,
    }
  }

  if $hostkeyalias {
    ssh_config{ "${_name}__HostKeyAlias":
      key    => 'HostKeyAlias',
      value  => $hostkeyalias,
      host   => $name,
      target => $target,
    }
  }

  if $hostname {
    ssh_config{ "${_name}__HostName":
      key    => 'HostName',
      value  => $hostname,
      host   => $name,
      target => $target,
    }
  }

  if $identityfile {
    ssh_config{ "${_name}__IdentityFile":
      key    => 'IdentityFile',
      value  => $identityfile,
      host   => $name,
      target => $target,
    }
  }

  if $kbdinteractivedevices {
    ssh_config{ "${_name}__KbdInteractiveDevices":
      key    => 'KbdInteractiveDevices',
      value  => $kbdinteractivedevices.join(','),
      host   => $name,
      target => $target,
    }
  }

  if $localcommand {
    ssh_config{ "${_name}__LocalCommand":
      key    => 'LocalCommand',
      value  => $localcommand,
      host   => $name,
      target => $target,
    }
  }

  if $localforward {
    ssh_config{ "${_name}__LocalForward":
      key    => 'LocalForward',
      value  => $localforward,
      host   => $name,
      target => $target,
    }
  }

  if $proxycommand {
    ssh_config{ "${_name}__ProxyCommand":
      key    => 'ProxyCommand',
      value  => $proxycommand,
      host   => $name,
      target => $target,
    }
  }

  if $rekeylimit {
    ssh_config{ "${_name}__RekeyLimit":
      key    => 'RekeyLimit',
      value  => $rekeylimit,
      host   => $name,
      target => $target,
    }
  }

  if $remoteforward {
    ssh_config{ "${_name}__RemoteForward":
      key    => 'RemoteForward',
      value  => $remoteforward,
      host   => $name,
      target => $target,
    }
  }

  if $smartcarddevice {
    ssh_config{ "${_name}__SmartcardDevice":
      key    => 'SmartcardDevice',
      value  => $smartcarddevice,
      host   => $name,
      target => $target,
    }
  }

  if $tunneldevice {
    ssh_config{ "${_name}__TunnelDevice":
      key    => 'TunnelDevice',
      value  => $tunneldevice,
      host   => $name,
      target => $target,
    }
  }

  if $user {
    ssh_config{ "${_name}__User":
      key    => 'User',
      value  => $user,
      host   => $name,
      target => $target,
    }
  }

  if $userknownhostsfile {
    ssh_config{ "${_name}__UserKnownHostsFile":
      key    => 'UserKnownHostsFile',
      value  => $userknownhostsfile.join(' '),
      host   => $name,
      target => $target,
    }
  }
}
