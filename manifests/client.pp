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
#   manages a keyword inside a drop-in file.  The ``ssh_config`` type only
#   manages ``Host`` blocks (``host`` defaults to ``*``); it cannot edit the
#   ``Match final all`` block that wraps the vendor client drop-ins
#   (``05-redhat.conf`` on EL8, ``50-redhat.conf`` on EL9+).  ssh applies a
#   ``Match final`` block in a final pass, and only for options nothing else
#   has set — so the reliable way to pin a client option is a drop-in of your
#   own that ssh reads *before* the vendor's: the first obtained value wins.
#   Do not point entries at the vendor files themselves.
#
#   * Each resource requires ``Package['openssh-clients']`` in addition to
#     any ``require`` the entry provides.
#
#   @example Disable GSSAPIAuthentication ahead of the vendor drop-in
#     ---
#     ssh::client::ssh_config_entries:
#       'simp GSSAPIAuthentication':
#         key: 'GSSAPIAuthentication'
#         value: 'no'
#         target: '/etc/ssh/ssh_config.d/00-simp.conf'
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

  # Raw ssh_config resources from Hiera (see the parameter docs).  Merge
  # (never replace) the package edge: an entry adding its own ordering
  # constraint must not lose the guarantee that openssh-clients is installed
  # before augeas touches its config files.
  $ssh_config_entries.each |$entry_title, $entry_attrs| {
    if 'require' in $entry_attrs {
      $_entry_require = [Package['openssh-clients']] + Array($entry_attrs['require'], true)
    } else {
      $_entry_require = Package['openssh-clients']
    }

    ssh_config { $entry_title:
      *       => $entry_attrs - ['require'],
      require => $_entry_require,
    }
  }
}
