# @summary Sets up a ssh client and creates /etc/ssh/ssh_config.
#
# A bare `include ssh` (or `include ssh::client`) installs the
# `openssh-clients` package and does *nothing else*.  The default `Host *`
# entry in `/etc/ssh/ssh_config` (and management of `ssh_config`/
# `ssh_known_hosts`) is opt-in via `$add_default_entry`.  Activate the bundled
# `simp:defaults` compliance_engine profile (or set `$add_default_entry`) to
# restore the pre-9.0.0 behavior.
#
# @param add_default_entry Set this if you wish to automatically
#   have the '*' Host entry set up with some sane defaults.
#
# @param fips If set or FIPS is already enabled, adjust for FIPS mode.
#
# @param haveged If true, include the haveged module to assist with entropy generation.
#
# @param package_ensure The ensure status the openssh-clients package
#
# @param ssh_config_entries
#   A Hash of raw ``ssh_config`` resources.  Each key is a resource title and
#   each value is a hash of attributes for the ``ssh_config`` type from
#   ``augeasproviders_ssh``, applied without validation.
#
#   This exposes the full type through Hiera — most notably ``target``, which
#   manages a keyword inside a drop-in file.  That is the supported way to
#   control a setting the vendor pre-sets under ``/etc/ssh/ssh_config.d/``
#   (``05-redhat.conf`` on EL8, ``50-redhat.conf`` on EL9+): ssh ``Include``s
#   that directory at the *top* of ``ssh_config`` and uses the first obtained
#   value, so a drop-in can silently override entries in the main file.
#
#   * Each resource requires ``Package['openssh-clients']`` unless the entry
#     provides its own ``require``.
#
#   @example Disable GSSAPIAuthentication in the vendor drop-in on EL9+
#     ---
#     ssh::client::ssh_config_entries:
#       '50-redhat GSSAPIAuthentication':
#         key: 'GSSAPIAuthentication'
#         value: 'no'
#         target: '/etc/ssh/ssh_config.d/50-redhat.conf'
#
# @author https://github.com/simp/pupmod-simp-ssh/graphs/contributors
#
class ssh::client (
  Boolean                                  $add_default_entry  = false,
  Boolean                                  $haveged            = false,
  Boolean                                  $fips               = false,
  String                                   $package_ensure     = 'installed',
  Hash[String[1],Hash[String[1],NotUndef]] $ssh_config_entries = {},
) {
  simplib::assert_metadata( $module_name )

  package { 'openssh-clients':
    ensure => $package_ensure
  }

  if $add_default_entry {
    ssh::client::host_config_entry { '*': }

    file { '/etc/ssh/ssh_config':
      owner                   => 'root',
      group                   => 'root',
      mode                    => '0644',
      selinux_ignore_defaults => true,
      require                 => Package['openssh-clients']
    }

    file { '/etc/ssh/ssh_known_hosts':
      owner => 'root',
      group => 'root',
      mode  => '0644'
    }
  }

  if $haveged {
    simplib::assert_optional_dependency($module_name, 'simp/haveged')

    include 'haveged'
  }

  # Raw ssh_config resources from Hiera (see the parameter docs).
  $ssh_config_entries.each |$entry_title, $entry_attrs| {
    ssh_config { $entry_title:
      * => { 'require' => Package['openssh-clients'] } + $entry_attrs,
    }
  }
}
