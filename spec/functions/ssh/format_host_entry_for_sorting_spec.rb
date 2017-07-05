require 'spec_helper'

describe 'ssh::format_host_entry_for_sorting' do
  testcases = {
    'foo.bar.baz'  => 'foo.bar.baz',
    '*'            => 'zzzz98_st__',
    '*.foo.bar'    => 'zzzz96_st__.foo.bar',
    'foo.*.bar'    => 'foo.zzzz95_st__.bar',
    'foo.bar.*'    => 'foo.bar.zzzz94_st__',
    'foo?.bar.baz' => 'foozzzz96_qu__.bar.baz',
    'foo.?bar.baz' => 'foo.zzzz95_qu__bar.baz',
    'foo.bar.b?z'  => 'foo.bar.bzzzz94_qu__z',
    'foo?.*.bar'   => 'foozzzz96_qu__.zzzz95_st__.bar',
  }

  context 'with valid input' do
    testcases.each do |input, expected_output|
      it { is_expected.to run.with_params(input).and_return(expected_output) }
    end
  end
end

