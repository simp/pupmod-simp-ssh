require 'spec_helper'

describe 'ssh' do
  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      let(:facts) do
        os_facts
      end

      context "on #{os}" do
        it { is_expected.to create_class('ssh') }
        it { is_expected.to compile.with_all_deps }
        it { is_expected.to create_file('/etc/ssh') }
        it { is_expected.to create_file('/etc/ssh/ssh_known_hosts') }
      end
    end
  end
end
