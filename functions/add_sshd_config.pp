# Add a sshd_config entry if it is not in the remove list
#
# @param key The name of the sshd configuration parameter
# @param value The value of the sshd configuration parameter
# @param remove_keys List of sshd configuration parameters to be removed
#
# @return [Nil]
#
function ssh::add_sshd_config(
  String[1]                       $key,
  Any                             $value,
  Variant[Array[String[1]],Undef] $remove_keys
) {

  $_add = ( $remove_keys == undef ) or ( !member($remove_keys, $key) )

  if $_add {
    sshd_config { $key: value => $value }
  }
}
