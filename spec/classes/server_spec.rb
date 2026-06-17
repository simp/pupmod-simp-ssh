require 'spec_helper'

# Resources that are only declared once service management is requested.
shared_examples_for 'a managed ssh server' do |os_facts|
  it { is_expected.to create_class('ssh::server') }
  it { is_expected.to compile.with_all_deps }
  it { is_expected.to contain_class('ssh') }

  it {
    is_expected.to create_file('/var/empty/sshd').with(
      ensure: 'directory',
      require: 'Package[openssh-server]',
    )
  }

  it {
    is_expected.to create_file('/var/empty/sshd/etc').with(
      ensure: 'directory',
      require: 'Package[openssh-server]',
    )
  }

  it {
    is_expected.to create_file('/var/empty/sshd/etc/localtime').with(
      source: 'file:///etc/localtime',
      require: 'Package[openssh-server]',
    )
  }

  it { is_expected.to contain_group('sshd') }

  it { is_expected.to contain_package('openssh-server').with_ensure('installed') }

  it {
    is_expected.to contain_user('sshd').with(
      ensure: 'present',
      allowdupe: false,
      gid: '74',
      uid: '74',
    )
  }

  it {
    is_expected.to contain_service('sshd').with(
      ensure: 'running',
      enable: true,
      require: [
        'Package[openssh-server]',
        'User[sshd]',
      ],
    )
  }

  os_facts[:ssh_host_keys].each do |host_key|
    it {
      is_expected.to create_file(host_key).with(
        owner: 'root',
        group: 'root',
        mode: '0600',
      )
    }

    it {
      is_expected.to create_file("#{host_key}.pub").with(
        owner: 'root',
        group: 'root',
        mode: '0644',
      )
    }
  end
end

describe 'ssh::server' do
  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:facts) do
          os_facts.merge(
            openssh_version: '6.6',
            timezone_file: '/etc/localtime',
          )
        end

        context 'with default parameters' do
          # Reduced blast radius: a bare include installs the package and does
          # nothing else.  Service management (and everything that only matters
          # when sshd runs) is opt-in.
          it { is_expected.to create_class('ssh::server') }
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_package('openssh-server').with_ensure('installed') }

          it { is_expected.not_to contain_service('sshd') }
          it { is_expected.not_to contain_user('sshd') }
          it { is_expected.not_to contain_group('sshd') }
          it { is_expected.not_to contain_file('/var/empty/sshd') }
          it { is_expected.not_to contain_file('/etc/ssh/moduli') }
          it { is_expected.not_to contain_file('/etc/ssh/sshd_config') }

          os_facts[:ssh_host_keys].each do |host_key|
            it { is_expected.not_to contain_file(host_key) }
          end
        end

        context 'with service management enabled' do
          let(:params) do
            {
              service_ensure: 'running',
              service_enable: true,
            }
          end

          it_behaves_like 'a managed ssh server', os_facts
          it { is_expected.not_to contain_package('openssh-ldap').with_ensure('installed') }
          it { is_expected.to contain_file('/etc/ssh/sshd_config').that_requires('Package[openssh-server]') }
        end

        context 'with service management and ldap => true' do
          # conf params are supplied via Hiera (APL); a resource-style
          # declaration of the private conf class trips assert_private.
          let(:hiera_config) do
            File.expand_path('../fixtures/hieradata/hiera_compliance_engine.yaml', __dir__)
          end
          let(:facts) do
            os_facts.merge(
              openssh_version: '6.6',
              timezone_file: '/etc/localtime',
              custom_hiera: 'server_ldap',
            )
          end
          let(:params) do
            {
              service_ensure: 'running',
              service_enable: true,
            }
          end

          it_behaves_like 'a managed ssh server', os_facts
          it { is_expected.to contain_package('openssh-ldap').with_ensure('installed') }
        end

        context 'with service management and pki => true' do
          let(:hiera_config) do
            File.expand_path('../fixtures/hieradata/hiera_compliance_engine.yaml', __dir__)
          end
          let(:facts) do
            os_facts.merge(
              openssh_version: '6.6',
              timezone_file: '/etc/localtime',
              custom_hiera: 'server_pki',
            )
          end
          let(:params) do
            {
              service_ensure: 'running',
              service_enable: true,
            }
          end

          it { is_expected.not_to contain_class('pki') }
          it { is_expected.to create_pki__copy('sshd') }
          it { is_expected.to create_file('/etc/pki/simp_apps/sshd/x509') }
          it {
            is_expected.to create_file('/etc/ssh/ssh_host_rsa_key').with(
              mode: '0600',
              source: 'file:///etc/pki/simp_apps/sshd/x509/private/foo.example.com.pem',
              subscribe: 'Pki::Copy[sshd]',
              notify: ['Exec[gensshpub]', 'Service[sshd]'],
            )
          }
          it {
            is_expected.to create_file('/etc/ssh/ssh_host_rsa_key.pub').with(
              mode: '0644',
              subscribe: 'Exec[gensshpub]',
            )
          }
          it {
            is_expected.to create_exec('gensshpub').with(
              refreshonly: true,
              require: ['Package[openssh-server]', 'File[/etc/ssh/ssh_host_rsa_key]'],
            )
          }
        end
      end
    end
  end
end
