[![License](http://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html) [![Build Status](https://travis-ci.org/simp/pupmod-simp-ssh.svg)](https://travis-ci.org/simp/pupmod-simp-ssh) [![SIMP compatibility](https://img.shields.io/badge/SIMP%20compatibility-4.2.*%2F5.1.*-orange.svg)](https://img.shields.io/badge/SIMP%20compatibility-4.2.*%2F5.1.*-orange.svg)


#SSH

#### Table of Contents

1. [Module Description - What the module does and why it is useful](#module-description)
2. [Setup - The basics of getting started with ssh](#setup)
    * [What ssh affects](#what-ssh-affects)
    * [Setup requirements](#setup-requirements)
    * [Beginning with ssh](#beginning-with-ssh)
3. [Usage - Configuration options and additional functionality](#usage)
4. [Reference]
5. [Limitations - OS compatibility, etc.](#limitations)
6. [Development - Guide for contributing to the module](#development)
7. [Acceptance Tests](#acceptance-tests)

## Module Description

Sets up SSH Client and Server

### Ciphers

By default, the `sshd::server` class will accept a wide range of ciphers.

At the time of 5.1.0, the default ciphers for `ssh::server` are:
- aes128-gcm@openssh.com
- aes256-gcm@openssh.com


There are also 'fallback' ciphers, which are required in order to communicate
with FIPS-140-2 conformant systems.  These are _also_ included by default unless
the parameter `ssh::server::conf::enable_fallback_ciphers` is set to `false`:
- aes128-cbc
- aes192-cbc
- aes256-cbc

## Setup

### What ssh affects

SSH installs the SSH package, runs the sshd service and manages files primarily
in /etc/ssh

### Setup requirements

The only requirement is including the ssh module in your modulepath

### Beginning with SSH

including `::ssh` will install both the server and the client

## Usage

### I want to manage only the server or the client

#### Server
```puppet
include 'sshd::server'
```
This will result in a server that accepts the following ciphers:
- aes128-gcm@openssh.com
- aes256-gcm@openssh.com
- aes128-cbc
- aes192-cbc
- aes256-cbc

#### Client
```puppet
include 'sshd::client'
```
The ciphers configured for the ssh client are set to only the strongest ciphers.
In order to connect to a system that does not have these ciphers but uses the
older ciphers you should use the command line option, `ssh -c`.  See the man
pages for further information.


### I want to disable fallback ciphers
```puppet
class{'ssh::config':
  enable_fallback_ciphers => false
}
include 'sshd::server'
```
This will result in a server that accepts the following ciphers:
- aes128-gcm@openssh.com
- aes256-gcm@openssh.com

## Reference

### Public Classes

* ssh
* ssh::client
* ssh::server
* ssh::server::conf

### Defined Types

* ssh::client::add_entry

### Class: `ssh`

#### Parameters

* `enable_client`: If true, set up the SSH client configuration files. Valid
Options: Boolean. Default: True

* `enable_client`: If true, set up the SSH server configuration files. Valid
Options: Boolean. Default: True

## Class: `ssh::client`

#### Parameters

* `add_default_entry`: Set this if you wish to automatically have the '*' host
entry set up with sane defaults. Valid Options: Boolean. Default: True

* `use_fips`: If set, adjust for FIPS mode. Default: False

* `use_haveged`: If true, include the haveged module to assist with entropy
generation. Default: True

### Class: `ssh::server`

#### Parameters

* `use_simp_pki`: If true, will include 'pki' and then use the certificates
that are transferred to generate the system SSH certificates for consistency.
Default: True

### Class: `ssh::server::conf`

#### Parameters

* `acceptenv`: Specifies what environment variables sent by the
client will be copied into the sessions enviornment. Valid Options: Array.

Default:
```puppet
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
],
```

* `authorizedkeysfile`: This is set to a non-standard location to
provide for increased control over who can log in as a given user. Valid
Options: String Default: /etc/ssh/local_keys/%u

* `authorizedkeyscommand`: Specifies a program to be used for
lookup of the user's public keys. Valid Options: Default: None

* `authorizedkeyscommanduser`: Specifies the user under whose
account the AuthorizedKeysCommand is run. Valid Options: String. Default:
'Nobody'

* `banner`: The contents of the specified file are sent to the
remote user before authentication is allowed. Valid Options: String. Default:
'/etc/issue.net'

* `challengeresponseauthentication`: Specifies whether challenge-response
authentication is allowed. Valid Options: Boolean. Default: False

* `ciphers`: Specifies the ciphers allowed for protocol version 2. Valid
Options: Array. Default: See ssh::server::params

* `compression`: Specifies whether compression is allowed, or
delayed until the user has authenticated successfully. Valid Options:
String. Valid Options: String. Default: False

* `fallback_ciphers`:  The set of ciphers that should be used should
no other cipher be declared. This is used when
$::ssh::server::enable_fallback_ciphers is enabled. Valid Options: Array.
Default: $::ssh::server::params::fallback_ciphers

* `enable_fallback_ciphers`: If true, add the fallback ciphers
from ssh::server::params to the cipher list. This is intended to provide
compatibility with non-SIMP systems in a way that properly supports FIPS
140-2. Valid Options: Boolean. Default: true

* `syslogfacility`: Gives the facility code that is used when
logging messages. Valid Options: 'DAEMON', 'USER', 'AUTH', 'AUTHPRIV',
'LOCAL0', 'LOCAL1', 'LOCAL2', 'LOCAL3', 'LOCAL4', 'LOCAL5', 'LOCAL6',
'LOCAL7'. Default: 'AUTHPRIV'

* `gssapiauthentication`: Specifies whether user authentication
based on GSSAPI is allowed. Valid Options: Boolean. Default: False

* `kex_algorithms`: Valid Options: Array.

* `listenaddress`: Specifies the local addresses sshd should listen

* `port`: Specifies the port number SSHD listens on. Valid Options: String.
Default: '22'.

* `macs`: Specifies the available MAC algorithms. Valid Options: Array.
Default: See $::ssh::server::params::macs

* `permitemptypasswords`: When password authentication is allowed,
it specifies whether the server allows login to accounts with empty password
strings. Valid Options: Boolean. Default: False

* `permitrootlogin`: Specifies whether root can log in using SSH.  Valid
Options: Boolean. Default: False

* `printlastlog`: Specifies whether SSHD should print the date and
time of the last user login when a user logs in interactively. Valid
Options: Boolean. Default: False

* `subsystem`: Configures and external subsystem for file
transfers. Valid Options: String. Default:
'sftp /usr/libexec/openssh/sftp-server'.

* `usepam`: Enables the Pluggable Authentication Module interface. Valid
Options: Boolean. Default: True

* `useprivilegeseparation`: Specifies whether sshd separates
privileges by creating an unprivileged child process to deal with incoming
network traffic. Valid Options: Boolean. Default: True

* `x11forwarding`:  Specifies whether X11 forwarding is permitted. Valid
Options: Boolean. Default: False

* `client_nets`: The networks to allow to connect to SSH. Valid Options: Array.
Default: 'any'

* `use_iptables`: If true, use the SIMP iptables class. Valid Options: Boolean.
Default:
```puppet
defined('$::use_iptables') ? {
  true => getvar('::use_iptables'),
  default => hiera('use_iptables', true)
}
```

* `use_ldap`: If true, enable LDAP support on the system. If
authorizedkeyscommand is empty, this will set the authorizedkeyscommand to
ssh-ldap-wrapper so that SSH public keys can be stored directly in LDAP. Valid
Options: Boolean.
Default:
```puppet
defined('$::use_ldap') ? {
  true => getvar('::use_ldap'),
  default => hiera('use_ldap', true)
},
```

* `use_tcpwrappers`:  If true, allow sshd tcpwrapper. Valid Options: Boolean.
Default: true

* `use_haveged`: If true, include the haveged module to assist with entropy
generation. Valid Options: Boolean. Default: true

* `use_sssd`: If true, use sssd. Valid Options: Boolean. Default: See

### Type: `ssh::client::add_entry`

#### Parameters

* `use_iptables`: If set, use the SIMP iptables module. Valid Options: Boolean.

* `name`: The 'Host' entry name.

* `address_family`: The IP Address family to use when connecting. Valid options:
'any', 'inet', 'inet6'. Valid Options: String. Default: any

* `batchmode`: If set to true, passphrase/password querying will be disabled.
This option is useful in scripts and other batch jobs where no user is present
to supply the password. Valid Options: Boolean. Default: false

* `bindaddress`: Use the specified address on the local machine as the source
address of the connection. Only useful on systems with more than one address.
Note that this option does not work if UsePrivilegedPort is set to false. Valid
Options: String. Default: None

* `challengeresponseauthentication`: Specifies whether to use challenge-response
authentication. Valid Options: Boolean. Default: True

* `checkhostip`: If this flag is set to true, ssh will additionally check the
host IP address in the known_hosts file. This allows ssh to detect if a host key
changed due to DNS spoofing and will add addresses of destination hosts to
~/.ssh/known_hosts in the process, regardless of the setting of
StrictHostKeyChecking. Valid Options: Boolean. Default: True.

* `cipher`: Specifies the cipher to use for encrypting the session in protocol
version 1. Valid Options: 'blowfish', '3des', 'des'. Default: '3des'

* `ciphers`: Specifies the ciphers allowed for protocol version 2 in order of
preference. Valid Options: Array.

* `clearallforwardings`: Specifies that all local, remote, and dynamic port
forwardings specified in the configuration files or on the command line be
cleared. Valid Options: Boolean. Default: False

* `compression`: Specifies whether to use compression. Valid Options: Boolean.
Default: True

* `compressionlevel`: Specifies the compression level to use if compression is
enabled. Valid Options: Integer. Default: 6

* `connectionattempts`: Specifies the number of tries (one per second) to make
before exiting. Valid Options: Integer. Default: 1

* `connecttimeout`: pecifies the timeout (in seconds) used when connecting to
the SSH server, instead of using the default system TCP timeout. Valid Options:
Integer. Default: 0

* `controlmaster`: Enables the sharing of multiple sessions over a single
network connection. Valid Options: Boolean. Default: False

* `controlpath`: String. Specify the path to the control socket used for
connection sharing as set by controlmaster. Valid Options: Default: None

* `dynamicforward`: Specifies that a TCP port on the local machine be forwarded
over the secure channel, and the application protocol is then used to determine
where to connect to from the remote machine. Valid Options: String. Default:
None

* `enablesshkeysign`: Setting this option to true enables the use of the helper
program ssh-keysign during HostbasedAuthentication. Valid Options: Boolean.
Default: False

* `escapechar`: Sets the default escape character. Valid Options: String.
Default: ~

* `exitonforwardfailure`: Specifies whether ssh should terminate the connection
if it cannot set up all requested dynamic, tunnel, local, and remote port
forwardings. Valid Options: Boolean. Default: False

* `forwardagent`: Specifies whether the connection to the authentication agent
(if any) will be forwarded to the remote machine. Valid Options: Boolean.
Default: False

* `forwardx11`: Specifies whether X11 connections will be automatically
redirected over the secure channel and DISPLAY set. Valid Options: Boolean.
Default: False

* `forwardx11trusted`: If set to true, remote X11 clients will have full access
to the original X11 display. Valid Options: Boolean. Default: False

* `gatewayports`: Specifies whether remote hosts are allowed to connect to local
forwarded ports. Valid Options: Boolean. Default: False

* `globalknownhostsfile`: Specifies one or more files to use for the global host
key database, separated by whitespace. Valid Options: String. Default: None

* `gssapiauthentication`: Specifies whether user authentication based on GSSAPI
is allowed. Valid Options: Boolean. Default: False

* `gssapidelegatecredentials`: Forward credentials to the server. Valid Options:
Boolean. Default: False

* `gssapikeyexchange`: Specifies whether key exchange based on GSSAPI may be
used. Valid Options: Boolean. Default: False

* `gssapirenewalforcesrekey`: If set to true then renewal of the client's GSSAPI
 credentials will force the rekeying of the ssh connection. Valid Options:
Boolean. Default: False

* `gssapitrustdns`: Set to true to indicate that the DNS is trusted to securely
canonicalize the name of the host being connected to. Valid Options: Boolean.
Default: False

* `hashknownhosts`: Indicates that SSH should hash host names and addresses when
they are added to known hosts. Valid Options: Boolean. Default: True

* `hostbasedauthentication`: Specifies whether to try rhosts based
authentication with public key authentication.  Valid Options: Boolean. Default:
True

* `hostkeyalgorithms`: Specifies the host key algorithms that the client wants
to use in order of preference. Valid Options: String. Default: 'ssh-rsa,ssh-dss'

* `hostkeyalias`: Specifies an alias that should be used instead of the real
host name when looking up or saving the host key in the host key database files.
Valid Options: String. Default: None

* `hostname`: Specifies the real hostname to log into. Valid Options: String.
Default: None

* `identitiesonly`: Specifies that ssh should only use the authentication
identity and certificate files explicitly configured in the ssh_config files or
passed on the ssh command-line, even if ssh-agent or a PKCS11Provider offers
more identities. Valid Options: Boolean. Default: False

* `identityfile`: Specifies a file from which the user's DSA, ECDSA, Ed25519 or
RSA authentication identity is read. Valid Options: String. Default: None

* `kbdinteractiveauthentication`: Specifies whether to use keyboard-interactive
authentication. Valid Options: Boolean. Default: True

* `kbdinteractivedevices`: Specifies the list of methods to use in
keyboard-interactive authentication. Multiple method names must be
comma-separated. Valid Options: String. Default: None

* `localcommand`: Specifies a command to execute on the local machine after
successfully connecting to the server. Valid Options: String. Default: None

* `localforward`: Specifies that a TCP port on the local machine be forwarded
over the secure channel to the specified host and port from the remote machine.
The first argument must be bind_address:port and the second argument must be
host:hostport. Valid Options: String. Default: None

* `macs`: Specifies the MAC (message authentication code) algorithms in order of
preference. Valid Options: Array. Default: None

* `ssh_loglevel`: Gives the verbosity level that is used when logging messages.
Valid options: 'QUIET', 'FATAL', 'ERROR', 'INFO', 'VERBOSE', 'DEBUG', 'DEBUG1',
'DEBUG2', and 'DEBUG3'. Valid Options: String. Default: 'INFO'

* `nohostauthenticationforlocalhost`: This option can be used if the home
directory is shared across machines. In this case localhost will refer to a
different machine on each of the machines and the user will get many warnings
about changed host keys. However, this option disables host authentication for
localhost. Valid Options: Boolean. Default: False

* `numberofpasswordprompts`: Specifies the number of password prompts before
giving up. Valid Options: Integer. Default: 3

* `passwordauthentication`: Specifies whether to use password authentication.
Valid Options: Boolean. Default: True

* `permitlocalcommand`: Allow local command execution via the LocalCommand
option or using the !command escape sequence. Valid Options: Boolean. Default:
False

* `port`: Specifies the port number to connect on the remote host. Valid
Options: Port. Default: 22

* `preferredauthentications`: Specifies the order in which the client should try
authentication methods. The order will be determined from the start of the array
to the end of the array. Valid Options: Array.
Default: ['publickey','hostbased','keyboard-interactive','password']

* `protocol`: Specifies the protocol version SSH should support in order of
preference. Valid Options: String. Default: 2

* `proxycommand`: Specifies the command to use to connect to the server.
Valid Options: String. Default: None

* `pubkeyauthentication`: Specifies whether to try public key authentication.
Valid Options: Boolean. Default: True

* `rekeylimit`: Specifies the maximum amount of data that may be transmitted
before the session key is renegotiated, optionally followed a maximum amount of
time that may pass before the session key is renegotiated. Valid Options:
String. Default: None

* `remoteforward`: Specifies that a TCP port on the remote machine be forwarded
over the secure channel to the specified host and port from the local machine.
Valid Options: String. Default: None

* `rhostsrsaauthentication`: Specifies whether to try rhosts based
authentication with RSA host authentication. Valid Options: Boolean. Default:
False

* `rsaauthentication`: Specifies whether to try RSA Authentication. Valid
Options: Boolean. Default: True

* `sendenv`: Specifies what variables from the local environment should be sent
to the server. Valid Options: Array. Default:

```puppet
['LANG',
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
'LC_ALL']
```

* `serveralivecountmax`: Sets the number of server alive messages (see below)
which may be sent without ssh receiving any messages back from the server. Valid
Options: Integer. Default: 3

* `serveraliveinterval`: Valid Options: Integer. Sets a timeout interval in
seconds after which if no data has been received from the server. The default is
0, indicating that these messages will not be sent to the server. Valid Options:
Integer. Default: 0

* `smartcarddevice`: Specifies which smartcard device to use. Valid Options:
String. Default: None

* `stricthostkeychecking`: If set to yes, ssh will never automatically add host
keys to the known_hosts file, and refuses to connect to hosts whose keys have
changed.  If this flag is set to “ask”, new host keys will be added to the user
known host files only after the user has confirmed that is what they really want
to do, and ssh will refuse to connect to hosts whose host key has changed. Valid
Options: String. Valid Options: 'yes', 'no', 'ask' Default: 'ask'

* `tcpkeepalive`: Specifies whether the system should send TCP keepalive
messages to the other side. Valid Options: Boolean. Default: True

* `tunnel`: Request device forwarding between the client and server. Valid
Options: String. Default: 'yes'

* `tunneldevice`: Specifies the devices to open on the client and the server.
Valid Options: String. Default: None

* `useprivilegedport`: Specifies whether to use a privileged port for outgoing
connections. Valid Options: Boolean. Default: False

* `user`: Specifies the user to log in as. Valid Options: String. Default: None

* `userknownhostsfile`: Specifies one or more files to use for the user host key
database, seperated by whitespace. Valid Options: String. Default: None

* `verifyhostkeydns`: Specifies whether to verify the remote key using DNS and
SSHFP resource records. Valid Options: Boolean. Default: False

* `visualhostkey`: If this flag is set to true, an ASCII art representation of
the remote host key fingerprint is printed in addition to the fingerprint string
at login and for unknown host keys. Valid Options: Boolean. Default: False

* `xauthlocation`: Specifies the full pathname of the xauth program. Valid
Options: String. Default: '/usr/bin/xauth'

## Limitations

SIMP Puppet modules are generally intended to be used on a Red Hat Enterprise
Linux-compatible distribution.

## Development

Please read our [Contribution Guide](https://simp-project.atlassian.net/wiki/display/SD/Contributing+to+SIMP)
and visit our [Developer Wiki](https://simp-project.atlassian.net/wiki/display/SD/SIMP+Development+Home)

If you find any issues, they can be submitted to our
[JIRA](https://simp-project.atlassian.net).

## Acceptance tests

To run the system tests, you need `Vagrant` installed.

You can then run the following to execute the acceptance tests:

```shell
   bundle exec rake beaker:suites
```

Some environment variables may be useful:

```shell
   BEAKER_debug=true
   BEAKER_provision=no
   BEAKER_destroy=no
   BEAKER_use_fixtures_dir_for_modules=yes
```

*  ``BEAKER_debug``: show the commands being run on the STU and their output.
*  ``BEAKER_destroy=no``: prevent the machine destruction after the tests
   finish so you can inspect the state.
*  ``BEAKER_provision=no``: prevent the machine from being recreated.  This can
   save a lot of time while you're writing the tests.
*  ``BEAKER_use_fixtures_dir_for_modules=yes``: cause all module dependencies
   to be loaded from the ``spec/fixtures/modules`` directory, based on the
   contents of ``.fixtures.yml``. The contents of this directory are usually
   populated by ``bundle exec rake spec_prep``. This can be used to run
   acceptance tests to run on isolated networks.
