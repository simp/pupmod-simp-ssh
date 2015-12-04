require 'spec_helper'

describe 'ssh::server::conf' do

  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      let(:facts) do
        facts
      end

      context "on #{os}" do
        shared_examples_for "a fact set conf" do
          it { is_expected.to create_class('ssh::server::conf') }
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_file('/etc/ssh/sshd_config') }
          it { is_expected.to create_file('/etc/ssh/local_keys') }
        end

        describe "RHEL 6" do
          it_behaves_like "a fact set conf"

          let(:facts) {{
            :fqdn => 'spec.test',
            :uid_min => '500',
            :grub_version => '0.97',
            :hardwaremodel => 'x86_64',
            :operatingsystem => 'RedHat',
            :operatingsystemmajrelease => '6',
            :operatingsystemmajrelease => '6',
            :interfaces => 'eth0,lo'
          }}
        end

        describe "RHEL 7" do
          it_behaves_like "a fact set conf"

          let(:facts) {{
            :fqdn => 'spec.test',
            :uid_min => '500',
            :grub_version => '2.0.2~beta2',
            :hardwaremodel => 'x86_64',
            :operatingsystem => 'RedHat',
            :operatingsystemmajrelease => '7',
            :operatingsystemmajrelease => '7',
            :interfaces => 'eth0,lo'
          }}
        end
      end
    end
  end
end
