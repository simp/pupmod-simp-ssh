require 'spec_helper'

describe 'ssh' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      let(:facts) do
        facts
      end

      context "on #{os}" do

        describe "a fact set init" do
          let(:facts) { facts.merge( { :openssh_version => '6.6' } ) }
          it { is_expected.to create_class('ssh') }
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_file('/etc/ssh') }
          it { is_expected.to create_file('/etc/ssh/ssh_host_key') }
          it { is_expected.to create_file('/etc/ssh/ssh_known_hosts') }
        end

      end
    end
  end
end
