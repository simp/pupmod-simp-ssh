require 'spec_helper'

describe 'ssh::parse_ssh_pubkey' do

  tests = [
    {
      content: 'ssh-rsa skjfhslkdjfs... kelly@test.local',
      result: {
        'type' => 'ssh-rsa',
        'key'  => 'skjfhslkdjfs...',
        'user' => 'kelly',
      }
    },
    {
      content: 'ssh-rsa skjfhslkdjfs... kelly',
      result: {
        'type' => 'ssh-rsa',
        'key'  => 'skjfhslkdjfs...',
        'user' => 'kelly',
      }
    },
    {
      content: 'ssh-rsa skjfhslkdjfs...',
      result: {
        'type' => 'ssh-rsa',
        'key'  => 'skjfhslkdjfs...',
      }
    },
  ]

  context 'with default secondary options' do
    tests.each do |params|
      it { is_expected.to run.with_params(params[:content]) \
        .and_return(params[:result]) }
    end
  end
end
