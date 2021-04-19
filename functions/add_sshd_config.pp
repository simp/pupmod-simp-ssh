# Add a sshd_config entry if it is not in the remove list
#
# @param key The name of the sshd configuration parameter
# @param value The value of the sshd configuration parameter
# @param remove_keys List of sshd configuration parameters to be removed
# @param resources_to_notify Catalog resources to notify when the sshd
#   configuration has changed
#
# @return [Nil]
#
function ssh::add_sshd_config(
  String[1]                       $key,
  Any                             $value,
  Variant[Array[String[1]],Undef] $remove_keys,
  Array[Type[Catalogentry]]       $resources_to_notify = [ Service['sshd'] ]
) {

  $_add = ( $remove_keys == undef ) or ( !member($remove_keys, $key) )

  if $_add {
    sshd_config { $key:
      value  => $value,
      notify => $resources_to_notify
    }
  }
}
