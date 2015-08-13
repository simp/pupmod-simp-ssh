require 'spec_helper'

describe 'ssh' do
  shared_examples_for "a fact set init" do
    it { should create_class('ssh') }
    it { should compile.with_all_deps }
    it { should create_file('/etc/ssh') }
    it { should create_file('/etc/ssh/ssh_host_key') }
    it { should create_file('/etc/ssh/ssh_known_hosts') }
  end

  describe "RHEL 6" do
    it_behaves_like "a fact set init"

    let(:facts) {{
      :fqdn => 'spec.test',
      :uid_min => '500',
      :grub_version => '0.97',
      :hardwaremodel => 'x86_64',
      :operatingsystem => 'RedHat',
      :lsbmajdistrelease => '6',
      :operatingsystemmajrelease => '6',
      :interfaces => 'eth0,lo'
    }}
  end

  describe "RHEL 7" do
    it_behaves_like "a fact set init"

    let(:facts) {{
      :fqdn => 'spec.test',
      :uid_min => '500',
      :grub_version => '0.97',
      :hardwaremodel => 'x86_64',
      :operatingsystem => 'RedHat',
      :lsbmajdistrelease => '7',
      :operatingsystemmajrelease => '7',
      :interfaces => 'eth0,lo'
    }}
  end
end
