require 'spec_helper'

describe 'ssh' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      let(:facts) do
        facts
      end

      context "on #{os}" do

        describe "a fact set init" do
          it { should create_class('ssh') }
          it { should compile.with_all_deps }
          it { should create_file('/etc/ssh') }
          it { should create_file('/etc/ssh/ssh_host_key') }
          it { should create_file('/etc/ssh/ssh_known_hosts') }
        end

      end
    end
  end
end
