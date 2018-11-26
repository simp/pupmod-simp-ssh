[![License](http://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html) [![Build Status](https://travis-ci.org/simp/pupmod-simp-ssh.svg)](https://travis-ci.org/simp/pupmod-simp-ssh) [![SIMP compatibility](https://img.shields.io/badge/SIMP%20compatibility-4.2.*%2F5.1.*-orange.svg)](https://img.shields.io/badge/SIMP%20compatibility-4.2.*%2F5.1.*-orange.svg)


# SSH

#### Table of Contents

<!-- vim-markdown-toc GFM -->

* [Module Description](#module-description)
* [Setup](#setup)
  * [What ssh affects](#what-ssh-affects)
  * [Setup requirements](#setup-requirements)
  * [Beginning with SSH](#beginning-with-ssh)
* [Usage](#usage)
  * [SSH client](#ssh-client)
    * [Managing client settings](#managing-client-settings)
    * [Managing client settings for specific hosts](#managing-client-settings-for-specific-hosts)
    * [Managing additional client settings using ``ssh_config``](#managing-additional-client-settings-using-ssh_config)
    * [Including the client by itself](#including-the-client-by-itself)
  * [SSH server](#ssh-server)
    * [Managing server settings](#managing-server-settings)
    * [Managing additional server settings using ``sshd_config``](#managing-additional-server-settings-using-sshd_config)
    * [Including the server by itself](#including-the-server-by-itself)
  * [Managing SSH ciphers](#managing-ssh-ciphers)
    * [Server ciphers](#server-ciphers)
    * [Client ciphers](#client-ciphers)
* [Limitations](#limitations)
* [Development](#development)
* [Acceptance tests](#acceptance-tests)
  * [Environment variables specific to pupmod-simp-ssh](#environment-variables-specific-to-pupmod-simp-ssh)

<!-- vim-markdown-toc -->

## Module Description

Manages the SSH Client and Server


## Setup

### What ssh affects

SSH installs the SSH package, runs the sshd service and manages files primarily
in `/etc/ssh`

### Setup requirements

The only requirement is including the ssh module in your modulepath

### Beginning with SSH

```puppet
include 'ssh'
```

## Usage

Including `ssh` will manage both the server and the client with "sane" settings:

```puppet
include 'ssh'
```

### SSH client

#### Managing client settings

Including `ssh::client` with no other options will automatically manage client
settings to be used with all hosts (`Host *`).

If you want to customize any of these settings, you must disable the creation
of the default entry with `ssh::client::add_default_entry: false` and manage
`Host *` manually with the defined type `ssh::client::host_config_entry`:

<!--
  Maintainers: You can validate these examples with the acceptance test
  "with customized settings" in `spec/acceptance/suites/default/ssh_spec.rb`.
-->

<!--
  This example demonstrates the client side of SIMP-4440.

  Acceptance test manifest = :client_manifest_w_custom_host_entries
-->

```puppet

class{ 'ssh::client': add_default_entry => false }

ssh::client::host_config_entry{ '*':
  gssapiauthentication      => true,
  gssapikeyexchange         => true,
  gssapidelegatecredentials => true,
}
```

#### Managing client settings for specific hosts

Including `ssh::client` will automatically manage client settings to be used
with all hosts (`Host *`).

Different settings for particular hosts can be managed by using the defined
type `ssh::client::host_config_entry`:

<!--
  Acceptance test manifest = :client_manifest_w_new_host
-->

```puppet
# `ancient.switch.fqdn` only understands old ciphers:
ssh::client::host_config_entry { 'ancient.switch.fqdn':
  ciphers => [ 'aes128-cbc', '3des-cbc' ],
}
```


#### Managing additional client settings using ``ssh_config``

If you need to customize a setting in `/etc/ssh/ssh_config` that
`ssh::client::host_config_entry` doesn't manage, use the
[`ssh_config`][aug_ssh__ssh_config] type, provided by augeasproviders_ssh:

<!--
  Acceptance test manifest = :client_manifest_w_ssh_config
-->

```puppet
# RequestTTY isn't handled by ssh::client::host_config_entry
ssh_config { 'Global RequestTTY':
  ensure => present,
  key    => 'RequestTTY',
  value  => 'auto',
}
```


#### Including the client by itself

```puppet
include `ssh::client`

```

You can prevent all inclusions of `ssh` from inadvertently managing the SSH
server by specifying `ssh::enable_server: false`:

```puppet
class{ 'ssh':
  enable_client => true,
  enable_server => false,
}
```


### SSH server

#### Managing server settings

Including `ssh::server` with the default options will manage the server with
reasonable settings for each host's environment.

If you want to customize any of these settings, you must edit the parameters of
`ssh::server::conf` using Hiera or ENC (Automatic Parameter Lookup).  These
customizations **_cannot be made directly_** using a resource-style
class declaration; they _must_ be made via APL:

```yaml
---
# Note: Hiera only!
ssh::server::conf::port: 2222
ssh::server::conf::ciphers:
- 'chacha20-poly1305@openssh.com'
- 'aes256-ctr'
- 'aes256-gcm@openssh.com
```

```puppet
include 'ssh::server'

# Alternative:
# if `ssh::enable_server: true`, this will also work
include 'ssh'
```


#### Managing additional server settings using ``sshd_config``

If you need to customize a setting in `/etc/ssh/sshd_config` that the
`ssh::server` class doesn't manage, use the
[`sshd_config`][aug_ssh__sshd_config]_ type, provided by
[augeasproviders_ssh][aug_ssh]

<!--
   Maintainers: You can validate these examples with the acceptance test
   "should permit additional settings via the sshd_config type" in
   spec/acceptance/suites/default/ssh_spec.rb
-->

```puppet
sshd_config {'LogLevel': value => 'VERBOSE'}
```

Some configurations may require a combination of `ssh::server::conf` and
`sshd_config`.  The following example configures the three
`/etc/ssh/sshd_config` keys **GSSAPIAuthentication**, **GSSAPIKeyExchange**,
and **GSSAPICleanupCredentials** with a value of "**yes**":

<!--
  This example demonstrates the server side of SIMP-4440 and SIMP-4197.

  Acceptance test hiera    = :server_hieradata_w_additions
  Acceptance test manifest = :server_manifest_w_additions
-->

Hiera:

```yaml
---
ssh::server::conf::gssapiauthentication: true

# GSSAPIKeyExchange + GSSAPICleanupCredentials are managed via sshd_config
```

Puppet:
```puppet
include 'ssh::server'

sshd_config {
  default:
    ensure => 'present',
    value  => 'yes',
  ;
  # GSSAPIAuthentication is managed via `ssh::server::conf::gssapiauthentication`
  ['GSSAPIKeyExchange', 'GSSAPICleanupCredentials']:
    # use defaults
  ;
}
```


#### Including the server by itself

You can focus `ssh` on managing the SSH server by itself by specifying
`ssh::enable_client: false`:

```puppet
class{ 'ssh':
  enable_client => false,
  enable_server => true,
}
```

Note: including `ssh::client` directly would still manage the SSH client


### Managing SSH ciphers

Unless instructed otherwise, the `ssh::` classes select ciphers based on the OS
environment (the OS version, the version of the SSH server, whether [FIPS
mode][fips_mode] is enabled, etc).

#### Server ciphers

<!--
   Maintainers: You can validate these examples by setting the environment
   variable `SIMP_SSH_report_dir` to a valid directory path while running
   the acceptance tests in spec/acceptance/suites/default/ssh_spec.rb.
-->

At the time of 6.4.0, the default ciphers for `ssh::server` on EL7 when FIPS
mode is _disabled_ are:

- `aes256-gcm@openssh.com`
- `aes128-gcm@openssh.com`
- `aes256-ctr`
- `aes192-ctr`
- `aes128-ctr`

There are also 'fallback' ciphers, which are required in order to communicate
with systems that are compliant with [FIPS-140-2][fips140_2].  These are
_always_ included by default unless the parameter
`ssh::server::conf::enable_fallback_ciphers` is set to `false`:

- `aes256-ctr`
- `aes192-ctr`
- `aes128-ctr`

At the time of 6.4.0, the 'fallback' ciphers are the default ciphers for
`ssh::server` on EL7 when FIPS mode is enabled and EL6 in either mode.


#### Client ciphers

By default, the system client ciphers in `/etc/ssh/ssh_config` are configured
to strong ciphers that are recommended for use.

If you need to connect to a system that does not support these ciphers but uses
older or weaker ciphers, you should either:
  - Manage an entry for that specific host using an additional
    `ssh::client::host_config_entry`, or:
  - Connect to the client with custom ciphers specified by the command line
    option, `ssh -c`
    * You can see a list of ciphers that your ssh client supports with `ssh -Q
      cipher`.
    * See the [ssh man pages][ssh_man] for further information.

Either of the choices above are preferable to weakening the system-wide
client settings unecessarily.


### Managing ssh_authorized_keys

You can manage users authorized_keys file using the ``ssh::authorized_keys``
class and the ``ssh::authorized_keys::keys`` hiera value.

```yaml
---
ssh::authorized_keys::keys:
  kelly: ssh-rsa skjfhslkdjfs...
  nick:
  - ssh-rsa sajhgfsaihd...
  - ssh-rsa jrklsahsgfs...
  mike:
    key: ssh-rsa dlfkjsahh...
    user: mlast
    target: /home/gitlab-runner/.ssh/authorized_keys
```


## Limitations

SIMP Puppet modules are generally intended to be used on a Red Hat Enterprise
Linux-compatible distribution.

## Development

Please read our [Contribution Guide][simp_contrib].

If you find any issues, they can be submitted to our
[JIRA](https://simp-project.atlassian.net).

To see a list of development tasks available for this module, run

      bundle exec rake -T

## Acceptance tests

To run the system tests, you need `Vagrant` installed.

You can then run the following to execute the acceptance tests:

```shell
   bundle exec rake beaker:suites
```

Some environment variables may be useful:

```shell
   BEAKER_debug=true
   BEAKER_destroy=onpass
   BEAKER_provision=no
   BEAKER_fips=yes
```

*  ``BEAKER_debug``: show the commands being run on the SUT and their output.
*  ``BEAKER_destroy=onpass`` prevent the machine destruction if the tests fail.
*  ``BEAKER_provision=no``: prevent the machine from being recreated.  This can
   save a lot of time while you're writing the tests.
*  ``BEAKER_fips=yes``:  Provision the SUTs in [FIPS mode][fips_mode].

### Environment variables specific to pupmod-simp-ssh

```shell
   SIMP_SSH_report_dir=/PATH/TO/DIRECTORY
```

* ``SIMP_SSH_report_dir``: If set to a valid directory, will record the Ciphers
  / MACs / kexalgorithms for each SSH server during the test.  This can be used
  to validate and update the information in the [Server
  ciphers](#server-ciphers) section.

[fips140_2]: https://csrc.nist.gov/publications/detail/fips/140/2/final
[ssh_man]: https://man.openbsd.org/ssh
[aug_ssh]: https://github.com/hercules-team/augeasproviders_ssh/
[aug_ssh__ssh_config]: https://github.com/hercules-team/augeasproviders_ssh#ssh_config-provider
[aug_ssh__sshd_config]: https://github.com/hercules-team/augeasproviders_ssh#sshd_config-provider
[simp_contrib]: simp.readthedocs.io/en/master/contributors_guide/
[fips_mode]: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/chap-federal_standards_and_regulations#sec-Enabling-FIPS-Mode
