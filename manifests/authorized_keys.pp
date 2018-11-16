# Add `ssh_authorized_keys` via hiera in a loop
#
# It was designed so you can just paste the output of the ssh pubkey into
# hiera and it will work. See the example below for details.
#
# > **WARNING**
# >
# > This creates a user for every key and every user in the Hash. If this is
# > large, please consider moving to a central source for these keys, such as
# > LDAP, so that you do not over-burden your Puppet server.
# >
# > **WARNING**
#
# @example
#   ```yaml
#   ssh::authorized_keys::keys:
#     kelly: ssh-rsa skjfhslkdjfs...
#     nick:
#     - ssh-rsa sajhgfsaihd...
#     - ssh-rsa jrklsahsgfs...
#     mike:
#       key: ssh-rsa dlfkjsahh...
#       user: mlast
#       target: /home/gitlab-runner/.ssh/authorized_keys
#   ```
#
# @param keys The hash to generate key resouces from
#
# @see https://puppet.com/docs/puppet/5.5/types/ssh_authorized_key.html
#
class ssh::authorized_keys (
  Hash $keys = {},
) {

  $expanded_keys = $keys.reduce({}) |Hash $result, Tuple $data| {
    $key_name = $data[0]
    $params   = $data[1]

    case $params {
      String: {
        $opts = ssh::parse_ssh_pubkey($params)
        $name = pick($opts['name'],$key_name)
        $title = "${name} - ${opts['key'][0,5]}..."
        $update = {
          $title => $opts + { 'user' => $key_name }
        }
      }
      Array: {
        $update = $params.reduce({}) |$memo, $key| {
          $opts = ssh::parse_ssh_pubkey($key)
          $name = pick($opts['name'],$key_name)
          $title = "${name} - ${opts['key'][0,5]}..."
          $memo + {
            $title => $opts + { 'user' => $key_name }
          }
        }
      }
      Hash: {
        $update = { $key_name => $params }
      }
      default: {
        $update = {}
      }
    }

    ($result + $update)
  }

  $expanded_keys.each |$key_name, $data| {
    ssh_authorized_key {
      $key_name: * => $data
    }
  }
}
