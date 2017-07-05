# Translates true|false or 'true'|'false' to 'yes'|'no', respectively
# All other values are passed-through unchanged
Puppet::Functions.create_function(:'ssh::config_bool_translate') do

  # @param config_item Configuration item to be translated
  # @return transformed config_item
  dispatch :config_bool_translate do
    required_param 'String', :config_item
  end

  # @param config_item Configuration item to be translated
  # @return transformed config_item
  dispatch :config_bool_translate do
    required_param 'Boolean', :config_item
  end

  def config_bool_translate(config_item)
    bool_translation = {
      true    => 'yes',
      'true'  => 'yes',
      false   => 'no',
      'false' => 'no'
    }

    return config_item if not bool_translation.keys.include?(config_item)

    bool_translation[config_item]
  end
end
