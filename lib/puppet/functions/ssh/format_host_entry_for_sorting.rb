# A method to sensibly format sort SSH 'host' entries which contain wildcards
# and question marks.
#
# The output is intended for use with the simpcat_fragment type and is *not*
# meant for use as a host entry itself.
#
# The general idea is that it places all items at the bottom of the list
# using zzzz, then sorts by question marks first per section then wildcards
# per section.
#
# Example:
# Input: '*'
# Output: 'zzzz98_st__'
#
# Input: '*.foo.bar'
# Output: 'zzzz96_st__.foo.bar'
#
# Input: 'foo.?.bar'
# Output: 'foo.zzzz95_qu__.bar'
#
# Input: 'foo?.*.bar'
# Output: 'foozzzz96_qu__.zzzz95_st__.bar'
Puppet::Functions.create_function(:'ssh::format_host_entry_for_sorting') do

  # @param host_entry  SSH host entry, which may contain wildcards
  # @return transformed host_entry
  dispatch :format_host_entry_for_sorting do
    required_param 'String', :host_entry
  end

  def format_host_entry_for_sorting(host_entry)
    segments = host_entry.split('.')
    refnum = 100 - segments.length

    segments.map {|x|
      refnum = refnum - 1
      x.gsub('*',"zzzz#{refnum}_st__").gsub('?',"zzzz#{refnum}_qu__")
    }.join('.')
  end
end
