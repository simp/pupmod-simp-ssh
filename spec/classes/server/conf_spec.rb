require 'spec_helper'

describe 'ssh::server::conf' do

  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      let(:facts) { facts }

      it { is_expected.to create_class('ssh::server::conf') }
      it { is_expected.to compile.with_all_deps }
      it { is_expected.to create_file('/etc/ssh/sshd_config') }
      it { is_expected.to create_file('/etc/ssh/local_keys') }
    end
  end
end
