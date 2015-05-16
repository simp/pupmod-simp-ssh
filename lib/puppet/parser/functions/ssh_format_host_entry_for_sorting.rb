module Puppet::Parser::Functions
  newfunction(:ssh_format_host_entry_for_sorting, :type => :rvalue, :doc => <<-'DOC', :arity => -1 ) do |args|
    A method to sensibly format sort SSH 'host' entries which contain wildcards
    and question marks.

    The output is intended for use with the concat_fragment type and is *not*
    meant for use as a host entry itself.

    The general idea is that it places all items at the bottom of the list
    using zzzz, then sorts by question marks first per section then wildcards
    per section.

    Example:
    Input: '*'
    '*.foo.bar','*','me.foo.*.bar','*.foo.bar','me.foo.?.bar'
    Output: 'zzzz98_st__'

    Input: '*.foo.bar'
    Output: 'zzzz96_st__.foo.bar'

    Input: 'foo.?.bar'
    Output: 'foo.zzzz95_qu__.bar'

    Input: 'foo?.*.bar'
    Output: 'foozzzz96_qu__.zzzz95_st__.bar'
    DOC

    val = args[0]
    val.is_a?(String) or raise(Puppet::Error,'You must pass a string to ssh_format_host_entry_for_sorting')
    result = val.dup
    segments = result.split('.')
    refnum = 100 - segments.length

    segments.map {|x|
      refnum = refnum - 1
      x.gsub('*',"zzzz#{refnum}_st__").gsub('?',"zzzz#{refnum}_qu__")
    }.join('.')
  end
end
