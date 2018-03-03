# Translate true/false into 'yes'/'no'
# @param  value  value to translate
# @return String 'yes' or 'no'
function ssh::ssh_bool_translate(
  Boolean $value,
) {
   $value ? {
     true  => 'yes',
     false => 'no',
   }
}

