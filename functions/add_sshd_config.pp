# Add a sshd_config entry if it has a value and is not in the remove list
#
# A `$value` of `undef` is skipped entirely so that an unset class parameter
# declares no `sshd_config` resource (reduced blast radius: Puppet leaves that
# setting exactly as the package/admin left it).
#
# The entry is written to the file `ssh::sshd_config_target` returns for the
# key: a drop-in that sorts first on EL9+, so vendor and installer drop-ins
# cannot override it, or `/etc/ssh/sshd_config`.  The drop-in is declared only
# once something is written to it.
#
# @param key The name of the sshd configuration parameter
# @param value The value of the sshd configuration parameter
# @param remove_keys List of sshd configuration parameters not to add,
#   compared case-insensitively
# @param resources_to_notify Catalog resources to notify when the sshd
#   configuration has changed.  Defaults to none, since the `sshd` service is
#   not managed unless service management is explicitly requested.
#
# @return [Nil]
#
function ssh::add_sshd_config(
  String[1]                       $key,
  Any                             $value,
  Variant[Array[String[1]],Undef] $remove_keys,
  Array[Type[Catalogentry]]       $resources_to_notify = []
) {
  # sshd keywords are case-insensitive, as is the sshd_config type's matching.
  $_add = ($value =~ NotUndef) and (( $remove_keys == undef ) or ( !(downcase($key) in $remove_keys.map |$k| { downcase($k) }) ))

  if $_add {
    $_target = ssh::sshd_config_target($key)

    if $_target {
      # Same attributes as 00-simp-kbdinteractive.conf: the CIS sshd_config.d
      # rules require root:root 0600, and without selinux_ignore_defaults the
      # augeas write leaves a SELinux user the next run would relabel.
      ensure_resource('file', $_target, {
        'ensure'                  => 'file',
        'owner'                   => 'root',
        'group'                   => 'root',
        'mode'                    => '0600',
        'selinux_ignore_defaults' => true,
        'require'                 => Package['openssh-server'],
      })

      $_require = [Package['openssh-server'], File[$_target]]
    }
    else {
      $_require = Package['openssh-server']
    }

    sshd_config { $key:
      value   => $value,
      target  => $_target,
      notify  => $resources_to_notify,
      require => $_require,
    }
  }
}
