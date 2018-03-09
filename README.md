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
    * [Manging client settings](#manging-client-settings)
    * [Managing particular `ssh_config` settings for different hosts](#managing-particular-ssh_config-settings-for-different-hosts)
    * [Managing the client by itself](#managing-the-client-by-itself)
  * [SSH server](#ssh-server)
    * [Managing server ettings](#managing-server-ettings)
    * [Managing the SSHD Server by itself](#managing-the-sshd-server-by-itself)
    * [Additional server customizations](#additional-server-customizations)
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

#### Manging client settings

Including `ssh::client` with no other options will automatically manage client
settings to be used with all hosts (`Host *`). If you want to customize any of
these settings, you must disable the creation of the default entry with
`ssh::client::add_default_entry: false` and manage `Host *` manually with the
defined type `ssh::client::host_config_entry`:

```puppet
# Disable default `Host *` entry in /etc/ssh/ssh_config
class{ 'ssh::client':
  add_default_entry => false,
}

# Specify `Host *` with the desired options
ssh::client::host_config_entry { '*':
  gssapiauthentication => true,
  forwardx11trusted    => true,
}
```

#### Managing particular `ssh_config` settings for different hosts

Including `ssh::client` will automatically manage client settings to be used
with all hosts (`Host *`).

Different settings for particular hosts can be managed by using the defined
type `ssh::client::host_config_entry`:

```puppet
# `ancient.switch.fqdn` only understands old ciphers:
ssh::client::host_config_entry { 'ancient.switch.fqdn':
   ciphers => [ 'aes128-cbc', '3des-cbc' ],
}
```

#### Managing the client by itself

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

#### Managing server ettings

Including `ssh::server` with no other options will automatically manage server
settings with reasonable defaults for the host's environment.  If you want to
customize any of these settings, you must edit the parameters of
`ssh::server::conf` via Automatic Parameter Lookup (e.g., Hiera or and ENC).

**NOTE:** These customizations cannot be made directly using a resource-style
class declaration; they _must_ be made via APL.

```yaml
---
# Hiera only!
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


#### Managing the SSHD Server by itself

You can focus `ssh` on managing the SSH server by itself by specifying
`ssh::enable_client: false`:

```puppet
class{ 'ssh':
  enable_client => false,
  enable_server => true,
}
```

Note: including `ssh::client` directly would still manage the SSH client


#### Additional server customizations

If you need to customize a setting in `/etc/ssh/sshd_config` that the `ssh::server` class doesn't manage, use the `sshd_config` type, provided by [augeasproviders_ssh][aug_ssh]

<!--
   Maintainers: You can validate these examples with the acceptance test
   "should permit additional settings via the sshd_config type" in
   spec/acceptance/suites/default/ssh_spec.rb
-->

```puppet
sshd_config {'LogLevel': value => 'VERBOSE'}
```


Some configurations may require a combination of `ssh::server::conf` and
`sshd_config`.  The following example configures the `/etc/ssh/sshd_config`
keys **GSSAPIAuthentication**, **GSSAPIKeyExchange**, and
**GSSAPICleanupCredentials** with a value of "**yes**":

Hiera:
```yaml
---
# SIMP-4440 example
ssh::server::conf::gssapiauthentication: true

# GSSAPIKeyExchange + GSSAPICleanupCredentials are managed via sshd_config
```

Puppet
```puppet
include 'ssh::server'

# SIMP-4440 example
sshd_config {
default:
  ensure => 'present',
  value  => 'yes',
;
['GSSAPIKeyExchange', 'GSSAPICleanupCredentials']:
  # use defaults
;
}
# GSSAPIAuthentication is managed via `ssh::server::conf::gssapiauthentication`
```


### Managing SSH ciphers

Unless instructed otherwise, the `ssh::` classes select ciphers based on the OS
environment (the OS version, the version of the SSH server, whether [FIPS mode][fips_mode] is enabled, etc).

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
with systems that are compliant with [FIPS-140-2][fips140_2].  These are _always_ included by default unless
the parameter `ssh::server::conf::enable_fallback_ciphers` is set to `false`:

- `aes256-ctr`
- `aes192-ctr`
- `aes128-ctr`

At the time of 6.4.0, the 'fallback' ciphers are the default ciphers for
`ssh::server` on EL7 when FIPS mode is enabled and EL6 in either mode.


#### Client ciphers

By default, the system client ciphers in `/etc/ssh/ssh_config` are configured
to strong ciphers that are recommended for use.

* If you need to connect to a system that does not support these ciphers but uses
  older or weaker ciphers, you should either:
  - Manage an entry for that specific host using an additional `ssh::client::host_config_entry`
  - Connect to the client using the command line option, `ssh -c`
* Either choice is preferable to configuring the system-wide client settings
  with weaker ciphers.
* You can see a list of ciphers that your ssh client supports with `ssh -Q
  cipher`.
* See the [ssh man pages][ssh_man] for further information.



## Limitations

SIMP Puppet modules are generally intended to be used on a Red Hat Enterprise
Linux-compatible distribution.

## Development

Please read our [Contribution Guide][simp_contrib] and visit our [Developer Wiki][simp_wiki]

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

### Environment variables specific to pupmod-simp-ssh

```shell
   SIMP_SSH_report_dir=/PATH/TO/DIRECTORY
```

* ``SIMP_SSH_report_dir``: If set to a valid directory, will record the Ciphers
  / MACs / kexalgorithms for each SSH server during the test.  This can be used
  to validate and update the information in the [Server
  ciphers][#server-ciphers] section.

[fips140_2]: https://csrc.nist.gov/publications/detail/fips/140/2/final
[ssh_man]: https://man.openbsd.org/ssh
[aug_ssh]: https://github.com/hercules-team/augeasproviders_ssh/
[simp_contrib]: simp.readthedocs.io/en/master/contributors_guide/
[simp_wiki]: https://simp-project.atlassian.net/wiki/display/SD/SIMP+Development+Home
[fips_mode]: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/chap-federal_standards_and_regulations#sec-Enabling-FIPS-Mode
