require 'spec_helper'

shared_examples_for "an ssh server" do |os_facts|
  it { is_expected.to create_class('ssh::server') }
  it { is_expected.to compile.with_all_deps }
  it { is_expected.to contain_class('ssh') }

  it { is_expected.to create_file('/var/empty/sshd').with({
      :ensure  => 'directory',
      :require => 'Package[openssh-server]'
    })
  }

  it { is_expected.to create_file('/var/empty/sshd/etc').with({
      :ensure  => 'directory',
      :require => 'Package[openssh-server]'
    })
  }

  it { is_expected.to create_file('/var/empty/sshd/etc/localtime').with({
      :source  => 'file:///etc/localtime',
      :require => 'Package[openssh-server]'
    })
  }

  it { is_expected.to contain_group('sshd') }

  it { is_expected.to contain_package('openssh-server').with_ensure('installed') }

  it { is_expected.to contain_user('sshd').with({
      :ensure    => 'present',
      :allowdupe => false,
      :gid       => '74',
      :uid       => '74'
    })
  }

  it { is_expected.to contain_service('sshd').with({
      :ensure  => 'running',
      :require => 'Package[openssh-server]'
    })
  }

  it { is_expected.to_not contain_exec('SELinux Allow SSH Port 22') }

  os_facts[:ssh_host_keys].each do |host_key|
    it { is_expected.to create_file(host_key).with({
        :owner => 'root',
        :group => 'root',
        :mode  => '0600'
      })
    }

    it { is_expected.to create_file("#{host_key}.pub").with({
        :owner => 'root',
        :group => 'root',
        :mode  => '0644'
      })
    }
  end
end

describe 'ssh::server' do
  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:facts) do
          os_facts
        end
        let(:facts) { os_facts.merge( { :openssh_version => '6.6' } ) }

        context "with default parameters" do
          it_behaves_like "an ssh server", os_facts
          it { is_expected.to_not contain_package('openssh-ldap').with_ensure('installed') }
        end

        context "with ldap => true" do
          let(:pre_condition){
            "class{'ssh::server::conf': ldap => true }"
          }
          it_behaves_like "an ssh server", os_facts
          it { is_expected.to contain_package('openssh-ldap').with_ensure('installed') }
        end

        context "with a non-standard ssh port" do
          let(:pre_condition){
            "class{'ssh::server::conf': port => 22000 }"
          }
          it { is_expected.to contain_package('policycoreutils-python').that_comes_before('Exec[SELinux Allow SSH Port 22000]') }
          it { is_expected.to contain_exec('SELinux Allow SSH Port 22000') }
        end

        context "with pki => true" do
          let(:pre_condition){
            "class{'ssh::server::conf': pki => true }"
          }
          it { is_expected.to_not contain_class('pki') }
          it { is_expected.to create_pki__copy('sshd')}
          it { is_expected.to create_file('/etc/pki/simp_apps/sshd/x509')}
          it { is_expected.to create_file('/etc/ssh/ssh_host_rsa_key').with({
              :mode      => '0600',
              :source    => "file:///etc/pki/simp_apps/sshd/x509/private/foo.example.com.pem",
              :subscribe => "Pki::Copy[sshd]",
              :notify    => ['Exec[gensshpub]', 'Service[sshd]']
            })
          }
          it { is_expected.to create_file('/etc/ssh/ssh_host_rsa_key.pub').with({
              :mode => '0644',
              :subscribe => 'Exec[gensshpub]'
            })
          }
          it { is_expected.to create_exec('gensshpub').with({
              :refreshonly => true,
              :require => ['Package[openssh-server]','File[/etc/ssh/ssh_host_rsa_key]']
            })
          }
        end
      end
    end
  end
end
