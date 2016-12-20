[![License](http://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html) [![Build Status](https://travis-ci.org/simp/pupmod-simp-ssh.svg)](https://travis-ci.org/simp/pupmod-simp-ssh) [![SIMP compatibility](https://img.shields.io/badge/SIMP%20compatibility-4.2.*%2F5.1.*-orange.svg)](https://img.shields.io/badge/SIMP%20compatibility-4.2.*%2F5.1.*-orange.svg)


#SSH

#### Table of Contents

1. [Module Description - What the module does and why it is useful](#module-description)
2. [Setup - The basics of getting started with ssh](#setup)
    * [What ssh affects](#what-ssh-affects)
    * [Setup requirements](#setup-requirements)
    * [Beginning with ssh](#beginning-with-ssh)
3. [Usage - Configuration options and additional functionality](#usage)
4. [Reference](#reference)
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

* [ssh](https://github.com/simp/pupmod-simp-ssh/blob/master/manifests/init.pp)
* [ssh::client](https://github.com/simp/pupmod-simp-ssh/blob/master/manifests/client.pp)
* [ssh::server](https://github.com/simp/pupmod-simp-ssh/blob/master/manifests/server.pp)
* [ssh::server::conf](https://github.com/simp/pupmod-simp-ssh/blob/master/manifests/server/conf.pp)

### Defined Types

* [ssh::client::host_config_entry](https://github.com/simp/pupmod-simp-ssh/blob/master/manifests/client/host_config_entry.pp)

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
