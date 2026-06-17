require 'spec_helper'

describe 'ssh::server::conf' do
  # sshd_config emission is driven by the parameters, not OS facts, so just use
  # the first supported OS as the base.
  let(:os_facts) { on_supported_os.first.last }
  let(:facts) { os_facts.merge(openssh_version: '8.0', fips_enabled: false) }

  context 'with no parameters (reduced blast radius)' do
    # A bare include leaves /etc/ssh/sshd_config exactly as the package left
    # it: no sshd_config resources, and the file itself is unmanaged because
    # the service is not managed.
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
    it { is_expected.not_to contain_class('iptables') }
    it { is_expected.not_to contain_class('tcpwrappers') }
    it { is_expected.not_to create_pki__copy('sshd') }
  end

  context 'with settings provided' do
    let(:params) do
      {
        banner: '/etc/issue.net',
        permitrootlogin: false,
        passwordauthentication: true,
        port: 22,
        maxauthtries: 6,
        clientaliveinterval: 600,
        x11forwarding: false,
        ciphers: ['aes256-ctr', 'aes192-ctr'],
        subsystem: 'sftp /usr/libexec/openssh/sftp-server',
        protocol: [2],
      }
    end

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
    let(:params) do
      {
        permitrootlogin: false,
        remove_entries: ['PermitRootLogin', 'GSSAPIAuthentication'],
      }
    end

    it { is_expected.to compile.with_all_deps }
    # A key in the remove list is not added even when its parameter is set...
    it { is_expected.to contain_sshd_config('PermitRootLogin').with_ensure('absent') }
    # ...and an explicit removal is declared.
    it { is_expected.to contain_sshd_config('GSSAPIAuthentication').with_ensure('absent') }
  end

  context 'with firewall => true' do
    let(:params) { { firewall: true, port: 22, trusted_nets: ['192.168.0.0/16'] } }

    it { is_expected.to compile.with_all_deps }
    it { is_expected.to contain_class('iptables') }
    it {
      is_expected.to contain_iptables__listen__tcp_stateful('allow_sshd').with(
        dports: [22],
        trusted_nets: ['192.168.0.0/16'],
      )
    }
  end

  context 'with tcpwrappers => true' do
    let(:params) { { tcpwrappers: true } }

    it { is_expected.to compile.with_all_deps }
    it { is_expected.to contain_class('tcpwrappers') }
    it { is_expected.to contain_tcpwrappers__allow('sshd') }
  end

  context 'with pki => true' do
    let(:params) { { pki: true } }

    it { is_expected.to compile.with_all_deps }
    it { is_expected.not_to contain_class('pki') }
    it { is_expected.to create_pki__copy('sshd') }
  end
end
