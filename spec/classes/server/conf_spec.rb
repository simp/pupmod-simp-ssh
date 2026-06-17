require 'spec_helper'

# `ssh::server::conf` is a private class configured via APL (Hiera).  It is
# declared here through `include ssh::server` (its public parent) so the
# in-module scope satisfies `assert_private`; parameters are supplied via Hiera
# rather than a resource-style declaration.
describe 'ssh::server::conf' do
  let(:hiera_config) do
    File.expand_path('../../fixtures/hieradata/hiera_compliance_engine.yaml', __dir__)
  end
  let(:pre_condition) { 'include ssh::server' }
  let(:base_facts) { on_supported_os.first.last.merge(openssh_version: '8.0', fips_enabled: false) }

  context 'with no sshd_config parameters (reduced blast radius)' do
    # A bare include leaves /etc/ssh/sshd_config exactly as the package left it.
    let(:facts) { base_facts.merge(custom_hiera: 'none') }

    it { is_expected.to compile.with_all_deps }
    it { is_expected.to create_class('ssh::server::conf') }
    it { is_expected.not_to contain_file('/etc/ssh/sshd_config') }
    it { is_expected.not_to contain_file('/etc/ssh/local_keys') }

    [
      'AcceptEnv', 'Banner', 'Ciphers', 'PermitRootLogin', 'PasswordAuthentication',
      'Port', 'MaxAuthTries', 'UsePAM', 'UsePrivilegeSeparation', 'X11Forwarding'
    ].each do |key|
      it { is_expected.not_to contain_sshd_config(key) }
    end

    it 'declares no sshd_config resources at all' do
      expect(catalogue.resources.select { |r| r.type == 'Sshd_config' }).to be_empty
    end

    it { is_expected.not_to contain_sshd_config_subsystem('sftp') }
  end

  context 'with sshd_config settings provided' do
    let(:facts) { base_facts.merge(custom_hiera: 'conf_settings') }

    it { is_expected.to compile.with_all_deps }
    it { is_expected.to contain_sshd_config('Banner').with_value('/etc/issue.net') }
    it { is_expected.to contain_sshd_config('Banner').that_requires('Package[openssh-server]') }
    it { is_expected.to contain_sshd_config('PermitRootLogin').with_value('no') }
    it { is_expected.to contain_sshd_config('PasswordAuthentication').with_value('yes') }
    it { is_expected.to contain_sshd_config('Port').with_value([22]) }
    it { is_expected.to contain_sshd_config('MaxAuthTries').with_value('6') }
    it { is_expected.to contain_sshd_config('ClientAliveInterval').with_value('600') }
    it { is_expected.to contain_sshd_config('X11Forwarding').with_value('no') }
    it { is_expected.to contain_sshd_config('Ciphers').with_value(['aes256-ctr', 'aes192-ctr']) }
    it { is_expected.to contain_sshd_config('Protocol').with_value('2') }
    it { is_expected.to contain_sshd_config_subsystem('sftp').with_command('/usr/libexec/openssh/sftp-server') }

    # Settings that were left unset declare no resource.
    it { is_expected.not_to contain_sshd_config('ListenAddress') }
    it { is_expected.not_to contain_sshd_config('LogLevel') }
    it { is_expected.not_to contain_sshd_config('AllowGroups') }
  end

  context 'with remove_entries' do
    let(:facts) { base_facts.merge(custom_hiera: 'conf_remove') }

    it { is_expected.to compile.with_all_deps }
    # A key in the remove list is not added even when its parameter is set...
    it { is_expected.to contain_sshd_config('PermitRootLogin').with_ensure('absent') }
    # ...and an explicit removal is declared.
    it { is_expected.to contain_sshd_config('GSSAPIAuthentication').with_ensure('absent') }
  end
end
