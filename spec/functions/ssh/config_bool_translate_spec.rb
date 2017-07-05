require 'spec_helper'

describe 'ssh::config_bool_translate' do
  testcases = {
    true    => 'yes',
    'true'  => 'yes',
    false   => 'no',
    'false' => 'no',
    'other' => 'other'
  }

  context 'with valid input' do
    testcases.each do |input, expected_output|
      it { is_expected.to run.with_params(input).and_return(expected_output) }
    end
  end
end

