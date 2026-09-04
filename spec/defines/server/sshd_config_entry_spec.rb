require 'spec_helper'

describe 'ssh::server::sshd_config_entry' do
  let(:hiera_config) do
    File.expand_path('../../fixtures/hieradata/hiera_compliance_engine.yaml', __dir__)
  end
  let(:title) { 'AuthorizedKeysFile GitLab user' }
  let(:params) do
    {
      key: 'AuthorizedKeysFile',
      condition: 'User git',
      value: '/var/opt/gitlab/.ssh/authorized_keys',
    }
  end

  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:base_facts) { os_facts.merge(openssh_version: '8.0', fips_enabled: false, timezone_file: '/etc/localtime') }

      context 'with the sshd service unmanaged (default)' do
        let(:facts) { base_facts.merge(custom_hiera: 'none') }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('ssh::server') }
        it { is_expected.not_to contain_service('sshd') }
        it {
          is_expected.to contain_sshd_config('AuthorizedKeysFile GitLab user')
            .with_ensure('present')
            .with_key('AuthorizedKeysFile')
            .with_condition('User git')
            .with_value('/var/opt/gitlab/.ssh/authorized_keys')
            .with_notify(nil)
            .that_requires('Package[openssh-server]')
        }
      end

      context 'with the sshd service managed' do
        let(:facts) { base_facts.merge(custom_hiera: 'server_service_managed') }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_service('sshd').with_ensure('running') }
        it {
          is_expected.to contain_sshd_config('AuthorizedKeysFile GitLab user')
            .that_requires('Package[openssh-server]')
            .that_notifies('Service[sshd]')
        }
      end

      context 'with ensure => absent in a drop-in file' do
        let(:facts) { base_facts.merge(custom_hiera: 'none') }
        let(:title) { '50-redhat GSSAPIAuthentication' }
        let(:params) do
          {
            ensure: 'absent',
            key: 'GSSAPIAuthentication',
            target: '/etc/ssh/sshd_config.d/50-redhat.conf',
          }
        end

        it { is_expected.to compile.with_all_deps }
        it {
          is_expected.to contain_sshd_config('50-redhat GSSAPIAuthentication')
            .with_ensure('absent')
            .with_key('GSSAPIAuthentication')
            .with_target('/etc/ssh/sshd_config.d/50-redhat.conf')
        }
      end

      context 'with the title as the keyword' do
        let(:facts) { base_facts.merge(custom_hiera: 'none') }
        let(:title) { 'MaxSessions' }
        let(:params) { { value: '5' } }

        it { is_expected.to contain_sshd_config('MaxSessions').with_key('MaxSessions').with_value('5') }
      end

      context 'with ensure => present and no value' do
        let(:facts) { base_facts.merge(custom_hiera: 'none') }
        let(:params) { { key: 'AuthorizedKeysFile' } }

        it { is_expected.to compile.and_raise_error(%r{'value' is required}) }
      end
    end
  end
end
