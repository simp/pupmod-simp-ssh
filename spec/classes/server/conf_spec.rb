require 'spec_helper'

describe 'ssh::server::conf' do

  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      let(:facts) do
        facts
      end

      context "on os #{os}" do
        let(:facts) { facts.merge( { :openssh_version => '6.6' } ) }

        context 'with default parameters' do
          let(:pre_condition){ 'include "::ssh"' }
          it { is_expected.to create_class('ssh::server::conf') }
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_file('/etc/ssh/sshd_config') }
          it { is_expected.to create_file('/etc/ssh/local_keys') }
          it { is_expected.to contain_class('haveged') }
        end
        context 'foo' do
          let(:params) {{:use_haveged => false}}
          it { is_expected.to_not contain_class('haveged') }
        end
      end
    end
  end
end
