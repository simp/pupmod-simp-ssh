require 'spec_helper'

# Proves that enabling the bundled `simp:defaults` compliance_engine profile
# restores the pre-8.0.0 behavior of `include ssh` (service management,
# hardening defaults, FIPS-aware crypto, and the SIMP integrations).
describe 'ssh' do
  let(:hiera_config) do
    File.expand_path('../fixtures/hieradata/hiera_compliance_engine.yaml', __dir__)
  end

  context 'with the simp:defaults profile enforced' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:facts) do
          os_facts.merge(
            openssh_version: '8.0',
            timezone_file: '/etc/localtime',
            fips_enabled: false,
            custom_hiera: 'simp_defaults_enforced',
          )
        end

        it { is_expected.to compile.with_all_deps }

        # Service management restored
        it {
          is_expected.to contain_service('sshd').with(
            ensure: 'running',
            enable: true,
          )
        }
        it { is_expected.to contain_user('sshd') }
        it { is_expected.to contain_group('sshd') }
        it { is_expected.to create_file('/var/empty/sshd') }
        it { is_expected.to create_file('/etc/ssh/sshd_config') }

        # Hardening defaults restored
        it { is_expected.to contain_sshd_config('PermitRootLogin').with_value('no') }
        it { is_expected.to contain_sshd_config('PasswordAuthentication').with_value('yes') }
        it { is_expected.to contain_sshd_config('Port').with_value([22]) }
        it { is_expected.to contain_sshd_config('Banner').with_value('/etc/issue.net') }
        it { is_expected.to contain_sshd_config('MaxAuthTries').with_value('6') }
        it { is_expected.to contain_sshd_config('UsePAM').with_value('yes') }
        it { is_expected.to contain_sshd_config('X11Forwarding').with_value('no') }
        it { is_expected.to contain_sshd_config_subsystem('sftp') }

        # Non-FIPS crypto restored
        it {
          is_expected.to contain_sshd_config('Ciphers').with_value(
            ['aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr', 'aes192-ctr', 'aes128-ctr'],
          )
        }

        # Client default Host entry restored
        it { is_expected.to create_ssh__client__host_config_entry('*') }
        it { is_expected.to contain_file('/etc/ssh/ssh_config') }

        # SIMP integrations restored to their typical site value
        it { is_expected.to contain_class('iptables') }
        it { is_expected.to contain_class('tcpwrappers') }
        it { is_expected.to contain_class('haveged') }
        it { is_expected.to create_pki__copy('sshd') }

        # UsePrivilegeSeparation is only valid on EL7 (confined in the profile)
        if os.split('-')[1] == '7'
          it { is_expected.to contain_sshd_config('UsePrivilegeSeparation').with_value('sandbox') }
        end
      end
    end
  end

  context 'with the profile enforced in FIPS mode' do
    let(:os_facts) { on_supported_os.first.last }
    let(:facts) do
      os_facts.merge(
        openssh_version: '8.0',
        timezone_file: '/etc/localtime',
        fips_enabled: true,
        custom_hiera: 'simp_defaults_enforced',
      )
    end

    it { is_expected.to compile.with_all_deps }
    it { is_expected.to contain_sshd_config('Ciphers').with_value(['aes256-ctr', 'aes192-ctr', 'aes128-ctr']) }
    it { is_expected.to contain_sshd_config('MACs').with_value(['hmac-sha2-256', 'hmac-sha1']) }
    it {
      is_expected.to contain_sshd_config('KexAlgorithms').with_value(
        ['ecdh-sha2-nistp521', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp256', 'diffie-hellman-group-exchange-sha256'],
      )
    }
  end

  context 'with an explicit site override on top of the profile' do
    let(:os_facts) { on_supported_os.first.last }
    let(:facts) do
      os_facts.merge(
        openssh_version: '8.0',
        timezone_file: '/etc/localtime',
        fips_enabled: false,
        custom_hiera: 'simp_defaults_with_override',
      )
    end

    it { is_expected.to compile.with_all_deps }

    # The site Hiera value (permitrootlogin: true) sits above the profile, so it
    # must win.  This guards that the profile is at *middle* Hiera priority.
    it { is_expected.to contain_sshd_config('PermitRootLogin').with_value('yes') }
  end
end
