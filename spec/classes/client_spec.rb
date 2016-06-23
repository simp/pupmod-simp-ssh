require 'spec_helper'

describe 'ssh::client' do

  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      let(:facts) do
        facts
      end

      context "on #{os}" do
        context 'with default parameters' do
          it { is_expected.to create_class('ssh::client') }
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_ssh__client__add_entry('*') }
          it { is_expected.to create_concat_build('ssh_config').with_target('/etc/ssh/ssh_config') }
          it { is_expected.to create_file('/etc/ssh/ssh_config') }
          it { is_expected.to contain_package('openssh-clients').with_ensure('latest') }
          it { is_expected.to contain_class('haveged') }
        end
        context 'with include_haveged = false' do
          let(:params) {{:use_haveged => false }}
          it { is_expected.to_not contain_class('haveged') }
        end
        context 'with invalid input' do
          let(:params) {{:use_haveged => 'invalid_input'}}
          it do
            expect {
              is_expected.to compile
            }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/invalid_input" is not a boolean/)
          end
        end
      end
    end
  end
end
