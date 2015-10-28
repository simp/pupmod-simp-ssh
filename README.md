[![License](http://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html) [![Build Status](https://travis-ci.org/simp/pupmod-simp-ssh.svg)](https://travis-ci.org/simp/pupmod-simp-ssh) [![SIMP compatibility](https://img.shields.io/badge/SIMP%20compatibility-4.2.*%2F5.1.*-orange.svg)](https://img.shields.io/badge/SIMP%20compatibility-4.2.*%2F5.1.*-orange.svg)

## This is a SIMP module
This module is a component of the [System Integrity Management Platform](https://github.com/NationalSecurityAgency/SIMP), a compliance-management framework built on Puppet.

If you find any issues, they can be submitted to our [JIRA](https://simp-project.atlassian.net/).

Please read our [Contribution Guide](https://simp-project.atlassian.net/wiki/display/SD/Contributing+to+SIMP) and visit our [developer wiki](https://simp-project.atlassian.net/wiki/display/SD/SIMP+Development+Home).

## Work in Progress

Please excuse us as we transition this code into the public domain.

## Ciphers
At the time of this build, the strongest ciphers for use in ssh are
        aes128-gcm@openssh.com
        aes256-gcm@openssh.com
Other allowable ciphers that can be included during install are:
        aes128-cbc
        aes192-cbc
        aes256-cbc
### Server
The ciphers configured for use with the ssh server can be set to include all allowable ciphers or to include only the strongest ciphers, by default it is set to install all allowable ciphers.  Initially only the strongest ciphers were installed but in order to allow users to ssh into the server without updating the code a change was made.  (SIMP-560).  A setting was placed in the simp_def.yaml file  ssh::server::use_strong_ciphers_only.  this parameter is defaulted to false and it will install all the allowable ciphers during the initial simp config.  You can change this at any time after the install by simply editing the simp_def.yaml file.
###Client
The ciphers configured for the ssh client are set to only the strongest ciphers.  In order to connect to a system that does not have these ciphers but uses the older ciphers you should use the command line option, 'ssh -c'.  See the man pages for further information.

Downloads, discussion, and patches are still welcome!
