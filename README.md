[![License](http://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html) [![Build Status](https://travis-ci.org/simp/pupmod-simp-ssh.svg)](https://travis-ci.org/simp/pupmod-simp-ssh) [![SIMP compatibility](https://img.shields.io/badge/SIMP%20compatibility-4.2.*%2F5.1.*-orange.svg)](https://img.shields.io/badge/SIMP%20compatibility-4.2.*%2F5.1.*-orange.svg)

## This is a SIMP module
This module is a component of the [System Integrity Management Platform](https://github.com/NationalSecurityAgency/SIMP), a compliance-management framework built on Puppet.

If you find any issues, they can be submitted to our [JIRA](https://simp-project.atlassian.net/).

Please read our [Contribution Guide](https://simp-project.atlassian.net/wiki/display/SD/Contributing+to+SIMP) and visit our [developer wiki](https://simp-project.atlassian.net/wiki/display/SD/SIMP+Development+Home).

## Work in Progress
Please excuse us as we transition this code into the public domain.



### ssh::server
#### Ciphers
By default, the `sshd::server` class will accept a wide range of ciphers.

At the time of 5.1.0, the default ciphers for `ssh::server` are:
- aes128-gcm@openssh.com
- aes256-gcm@openssh.com


There are also 'fallback' ciphers, which are required in order to communicate with FIPS-140-2 conformant systems.  These are _also_ included by default unless the parameter `ssh::server::conf::enable_fallback_ciphers` is set to `false`:
- aes128-cbc
- aes192-cbc
- aes256-cbc

#### Examples
##### Default parameters
```puppet
include 'sshd::server'
```
This will result in a server that accepts the following ciphers:
- aes128-gcm@openssh.com
- aes256-gcm@openssh.com
- aes128-cbc
- aes192-cbc
- aes256-cbc


##### Disabling fallback ciphers
```puppet
class{'ssh::config':
  enable_fallback_ciphers => false
}
include 'sshd::server'
```
This will result in a server that accepts the following ciphers:
- aes128-gcm@openssh.com
- aes256-gcm@openssh.com



### ssh::client
The ciphers configured for the ssh client are set to only the strongest ciphers.  In order to connect to a system that does not have these ciphers but uses the older ciphers you should use the command line option, `ssh -c`.  See the man pages for further information.

#### Examples
```puppet
include 'sshd::client'
```
