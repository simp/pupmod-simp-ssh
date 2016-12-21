module Puppet::Parser::Functions
  newfunction(:ssh_config_bool_translate, :type => :rvalue, :doc => "Translates true|false to yes|no, respectively." ) do |args|
    to_translate = args[0]

    bool_translation = {
      true    => 'yes',
      'true'  => 'yes',
      false   => 'no',
      'false' => 'no'
    }

    return to_translate if not bool_translation.keys.include?(to_translate)

    bool_translation[to_translate]
  end
end
