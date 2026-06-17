# Add a sshd_config entry if it has a value and is not in the remove list
#
# A `$value` of `undef` is skipped entirely so that an unset class parameter
# declares no `sshd_config` resource (reduced blast radius: Puppet leaves that
# setting exactly as the package/admin left it).
#
# @param key The name of the sshd configuration parameter
# @param value The value of the sshd configuration parameter
# @param remove_keys List of sshd configuration parameters to be removed
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

  $_add = ($value =~ NotUndef) and (( $remove_keys == undef ) or ( !member($remove_keys, $key) ))

  if $_add {
    sshd_config { $key:
      value   => $value,
      notify  => $resources_to_notify,
      require => Package['openssh-server'],
    }
  }
}
