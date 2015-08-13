require 'spec_helper'

describe 'ssh::server' do

  shared_examples_for "a fact set server" do
    it { should create_class('ssh::server') }
    it { should compile.with_all_deps }
    it { should contain_class('ssh') }

    it { should create_file('/var/empty/sshd').with({
        :ensure  => 'directory',
        :require => 'Package[openssh-server]'
      })
    }

    it { should create_file('/var/empty/sshd/etc').with({
        :ensure  => 'directory',
        :require => 'Package[openssh-server]'
      })
    }

    it { should create_file('/var/empty/sshd/etc/localtime').with({
        :source  => '/etc/localtime',
        :require => 'Package[openssh-server]'
      })
    }

    it { should contain_group('sshd') }

    it { should contain_package('openssh-server').with_ensure('latest') }
    it { should contain_package('openssh-ldap').with_ensure('latest') }

    it { should contain_user('sshd').with({
        :ensure    => 'present',
        :allowdupe => false,
        :gid       => '74',
        :uid       => '74'
      })
    }

    it { should contain_service('sshd').with({
        :ensure  => 'running',
        :require => 'Package[openssh-server]'
      })
    }
  end

  describe "RHEL 6" do
    it_behaves_like "a fact set server"

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
    it_behaves_like "a fact set server"

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
