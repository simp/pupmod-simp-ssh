# Taka an ssh pugkey that looks like:
#   ssh-rsa jdlkfgjsdfo;i... user@domain.com
# and turn it into a hash, usable in the ssh_authorized_key type
#
# @param key The ssh key, can be pasted from ~/.ssh/id_rsa.pub or similar
#
# @return [Hash]
#
function ssh::parse_ssh_pubkey(String $key) {
  $split = $key.split(' ')


  $base = {
    'key'  => $split[1],
    'type' => $split[0],
  }

  $user = $split[2]
  if $user {
    $out = $base + {
      'user' => $user.split('@')[0],
    }
  }
  else {
    $out = $base
  }

  $out
}
