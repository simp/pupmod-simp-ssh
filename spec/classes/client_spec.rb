require 'spec_helper'

describe 'ssh::client' do

  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      let(:facts) do
        facts
      end

      context "on #{os}" do

        it { is_expected.to create_class('ssh::client') }
        it { is_expected.to compile.with_all_deps }
        it { is_expected.to create_ssh__client__add_entry('*') }
        it { is_expected.to create_concat_build('ssh_config').with_target('/etc/ssh/ssh_config') }
        it { is_expected.to create_file('/etc/ssh/ssh_config') }
        it { is_expected.to contain_package('openssh-clients').with_ensure('latest') }
      end
    end
  end
end
