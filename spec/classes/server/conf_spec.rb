require 'spec_helper'

describe 'ssh::server::conf' do

  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      let(:facts) do
        facts
      end

      context "on os #{os}" do

        context 'with default parameters, openssh_version=5.3, both simp_options::fips and fips_enabled false' do
          let(:facts) { os_facts.merge( { :openssh_version => '5.3', :fips_enabled => false } ) }
          let(:pre_condition){ 'include "::ssh"' }

          it { is_expected.to create_class('ssh::server::conf') }
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_file('/etc/ssh/sshd_config') }
          it { is_expected.to contain_sshd_config('AcceptEnv').with_value(
            [ 'LANG', 'LC_CTYPE', 'LC_NUMERIC', 'LC_TIME', 'LC_COLLATE', 'LC_MONETARY',
              'LC_MESSAGES', 'LC_PAPER', 'LC_NAME', 'LC_ADDRESS', 'LC_TELEPHONE',
              'LC_MEASUREMENT', 'LC_IDENTIFICATION', 'LC_ALL'
            ]
          ) }
          it { is_expected.to contain_sshd_config('AuthorizedKeysFile').with_value('/etc/ssh/local_keys/%u') }
          it { is_expected.to contain_sshd_config('Banner').with_value('/etc/issue.net') }
          it { is_expected.to contain_sshd_config('ChallengeResponseAuthentication').with_value('no') }
          it {
            if (['RedHat', 'CentOS'].include?(facts[:os][:name])) and
              (facts[:os][:release][:major].to_s >= '7')
              expected_ciphers = ['aes256-gcm@openssh.com', 'aes128-gcm@openssh.com',
                                  'aes256-ctr', 'aes192-ctr', 'aes128-ctr' ]
              expected_macs = [ 'hmac-sha2-512-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com',
               'hmac-sha2-512', 'hmac-sha2-256' ]
              is_expected.to contain_sshd_config('UsePrivilegeSeparation').with_value('sandbox')
            else
              expected_ciphers = ['aes256-ctr', 'aes192-ctr', 'aes128-ctr' ]
              expected_macs = [ 'hmac-sha1' ]
              is_expected.to contain_sshd_config('UsePrivilegeSeparation').with_value('yes')
            end

            is_expected.to contain_sshd_config('Ciphers').with_value(expected_ciphers)
            is_expected.to contain_sshd_config('MACs').with_value(expected_macs)
          }
          it { is_expected.to contain_sshd_config('Compression').with_value('no') }
          it { is_expected.to contain_sshd_config('SyslogFacility').with_value('AUTHPRIV') }
          it { is_expected.to contain_sshd_config('GSSAPIAuthentication').with_value('no') }
          it { is_expected.to_not contain_sshd_config('KexAlgorithms') }
          it { is_expected.to contain_sshd_config('ListenAddress').with_value('0.0.0.0') }
          it { is_expected.to contain_sshd_config('Port').with_value('22') }
          it { is_expected.to contain_sshd_config('PermitEmptyPasswords').with_value('no') }
          it { is_expected.to contain_sshd_config('PermitRootLogin').with_value('no') }
          it { is_expected.to contain_sshd_config('PrintLastLog').with_value('no') }
          it { is_expected.to contain_sshd_config('UsePAM').with_value('yes') }
          it { is_expected.to contain_sshd_config('X11Forwarding').with_value('no') }
          it { is_expected.to_not contain_sshd_config('AuthorizedKeysCommand') }
          it { is_expected.to_not contain_sshd_config('AuthorizedKeysCommandUser') }
          it { is_expected.to create_file('/etc/ssh/local_keys') }
          it { is_expected.to_not contain_class('iptables') }
          it { is_expected.to_not contain_class('tcpwrappers') }
          it { is_expected.to_not contain_class('haveged') }
        end

        context 'with default parameters, openssh_version=6.6, both simp_options::fips and fips_enabled false' do
          let(:facts) { os_facts.merge( { :openssh_version => '6.6', :fips_enabled => false } ) }
          let(:pre_condition){ 'include "::ssh"' }

          it { is_expected.to compile.with_all_deps }
          it {
            if (['RedHat', 'CentOS'].include?(facts[:os][:name])) and
              (facts[:os][:release][:major].to_s >= '7')
              expected_ciphers = [ 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr',
               'aes192-ctr', 'aes128-ctr' ]

              expected_macs = [ 'hmac-sha2-512-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com',
               'hmac-sha2-512', 'hmac-sha2-256' ]

              expected_kex_algorithms = [ 'curve25519-sha256@libssh.org', 'ecdh-sha2-nistp521',
                'ecdh-sha2-nistp384', 'ecdh-sha2-nistp256', 'diffie-hellman-group-exchange-sha256']
            else
              expected_ciphers = ['aes256-ctr', 'aes192-ctr', 'aes128-ctr' ]
              expected_macs = [ 'hmac-sha1' ]
              expected_kex_algorithms = ['diffie-hellman-group-exchange-sha256']
            end

            is_expected.to contain_sshd_config('Ciphers').with_value(expected_ciphers)
            is_expected.to contain_sshd_config('MACs').with_value(expected_macs)
            is_expected.to contain_sshd_config('KexAlgorithms').with_value(expected_kex_algorithms)
          }
        end

        context 'with default parameters, openssh_version=5.3, simp_options::fips=true and fips_enabled=false' do
          let(:facts) { os_facts.merge( { :openssh_version => '5.3', :fips_enabled => false } ) }
          let(:hieradata) { 'fips_catalyst_enabled' }
          let(:pre_condition){ 'include "::ssh"' }

          it { is_expected.to compile }
          it {
            if (['RedHat', 'CentOS'].include?(facts[:os][:name])) and
              (facts[:os][:release][:major].to_s >= '7')
              expected_ciphers = [ 'aes256-ctr', 'aes192-ctr', 'aes128-ctr' ]

              expected_macs = [ 'hmac-sha2-256', 'hmac-sha1' ]
            else
              expected_ciphers = ['aes256-ctr', 'aes192-ctr', 'aes128-ctr' ]
              expected_macs = [ 'hmac-sha1' ]
            end

            is_expected.to contain_sshd_config('Ciphers').with_value(expected_ciphers)
            is_expected.to contain_sshd_config('MACs').with_value(expected_macs)
          }
          it { is_expected.to_not contain_sshd_config('KexAlgorithms') }
        end

        context 'with default parameters, openssh_version=6.6, simp_options::fips=false and fips_enabled=true' do
          let(:facts) { os_facts.merge( { :openssh_version => '6.6', :fips_enabled => true } ) }
          let(:pre_condition){ 'include "::ssh"' }

          it { is_expected.to compile.with_all_deps }
          it {
            if (['RedHat', 'CentOS'].include?(facts[:os][:name])) and
              (facts[:os][:release][:major].to_s >= '7')
              expected_ciphers = [ 'aes256-ctr', 'aes192-ctr', 'aes128-ctr' ]

              expected_macs = [ 'hmac-sha2-256', 'hmac-sha1' ]

              expected_kex_algorithms = [ 'ecdh-sha2-nistp521', 'ecdh-sha2-nistp384',
                'ecdh-sha2-nistp256', 'diffie-hellman-group-exchange-sha256']
            else
              expected_ciphers = ['aes256-ctr', 'aes192-ctr', 'aes128-ctr' ]
              expected_macs = [ 'hmac-sha1' ]
              expected_kex_algorithms = ['diffie-hellman-group-exchange-sha256']
            end

            is_expected.to contain_sshd_config('Ciphers').with_value(expected_ciphers)
            is_expected.to contain_sshd_config('MACs').with_value(expected_macs)
            is_expected.to contain_sshd_config('KexAlgorithms').with_value(expected_kex_algorithms)
          }
        end

        context 'with enable_fallback_ciphers=false' do
          let(:facts) { os_facts.merge( { :openssh_version => '6.6', :fips_enabled => false } ) }
          let(:hieradata) { 'enable_fallback_ciphers_disabled' }
          let(:pre_condition){ 'include "::ssh"' }

          it { is_expected.to compile.with_all_deps }
          it {
            if (['RedHat', 'CentOS'].include?(facts[:os][:name])) and
              (facts[:os][:release][:major].to_s >= '7')
              expected_ciphers = ['aes256-gcm@openssh.com', 'aes128-gcm@openssh.com',
                                  'aes256-ctr', 'aes192-ctr', 'aes128-ctr' ]
            else
              expected_ciphers = ['aes256-ctr', 'aes192-ctr', 'aes128-ctr' ]
            end
            is_expected.to contain_sshd_config('Ciphers').with_value(expected_ciphers)
          }
        end

        context 'with authorizedkeyscommand and authorizedkeyscommanduser set' do
          let(:facts) { os_facts.merge( { :openssh_version => '6.6', :fips_enabled => true } ) }
          let(:hieradata) { 'authorizedkeyscommand' }
          let(:pre_condition){ 'include "::ssh"' }

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_sshd_config('AuthorizedKeysCommand').with_value('/some/command') }
          it {
            if (['RedHat', 'CentOS'].include?(facts[:os][:name])) and
              (facts[:os][:release][:major].to_s >= '7')
              is_expected.to contain_sshd_config('AuthorizedKeysCommandUser').with_value('nobody')
            else
              is_expected.to_not contain_sshd_config('AuthorizedKeysCommandUser')
            end
          }
        end

        context 'with authorizedkeyscommand set but authorizedkeyscommanduser empty' do
          let(:facts) { os_facts.merge( { :openssh_version => '6.6', :fips_enabled => true } ) }
          let(:hieradata) { 'authorizedkeyscommand_with_empty_user' }
          let(:pre_condition){ 'include "::ssh"' }

          it {
            if (['RedHat', 'CentOS'].include?(facts[:os][:name])) and
              (facts[:os][:release][:major].to_s >= '7')
              is_expected.to_not compile.with_all_deps
            else
              is_expected.to compile.with_all_deps
            end
          }
        end

        context 'with useprivilegeseparation' do
          let(:facts) { os_facts.merge( { :openssh_version => '6.6' } ) }
          let(:pre_condition){ "service {'sshd':}" }

          context '=> true' do
            let(:params) {{ :useprivilegeseparation => true }}
            it { is_expected.to contain_sshd_config('UsePrivilegeSeparation').with_value('yes') }
          end
          context '=> false' do
            let(:params) {{ :useprivilegeseparation => false }}
            it { is_expected.to contain_sshd_config('UsePrivilegeSeparation').with_value('no') }
          end
        end

        context 'with both simp_options::ldap and simp_options::ssd true' do
          let(:facts) { os_facts.merge( { :openssh_version => '6.6', :fips_enabled => true } ) }
          let(:hieradata) { 'ldap_and_sssd' }
          let(:pre_condition){ 'include "::ssh"' }

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_class('sssd::install') }
          it { is_expected.to contain_sshd_config('AuthorizedKeysCommand').with_value('/usr/bin/sss_ssh_authorizedkeys') }
          it {
            if (['RedHat', 'CentOS'].include?(facts[:os][:name])) and
              (facts[:os][:release][:major].to_s >= '7')
              is_expected.to contain_sshd_config('AuthorizedKeysCommandUser').with_value('nobody')
            else
              is_expected.to_not contain_sshd_config('AuthorizedKeysCommandUser')
            end
          }
        end

        context 'with simp_options::ldap = true, but simp_options::ssd = false' do
          let(:facts) { os_facts.merge( { :openssh_version => '6.6', :fips_enabled => true } ) }
          let(:hieradata) { 'ldap_only' }
          let(:pre_condition){ 'include "::ssh"' }

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to_not contain_class('sssd::install') }
          it { is_expected.to contain_sshd_config('AuthorizedKeysCommand').with_value('/usr/libexec/openssh/ssh-ldap-wrapper') }
          it {
            if (['RedHat', 'CentOS'].include?(facts[:os][:name])) and
              (facts[:os][:release][:major].to_s >= '7')
              is_expected.to contain_sshd_config('AuthorizedKeysCommandUser').with_value('nobody')
            else
              is_expected.to_not contain_sshd_config('AuthorizedKeysCommandUser')
            end
          }
        end

        context 'with firewall, haveged, pam, and tcpwrappers global catalysts enabled' do
          let(:facts) { os_facts.merge( { :openssh_version => '6.6', :fips_enabled => true } ) }
          let(:hieradata) { 'some_global_catalysts_enabled' }
          let(:pre_condition){ 'include "::ssh"' }

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_sshd_config('UsePAM').with_value('yes') }
          it { is_expected.to contain_class('iptables') }
          it { is_expected.to contain_class('tcpwrappers') }
          it { is_expected.to contain_class('haveged') }
        end

        context 'when connected to an IPA domain' do
          let(:pre_condition){ 'include "::ssh"' }
          let(:facts) {
            os_facts.merge(
              ipa: {}
            )
          }

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_sshd_config('GSSAPIAuthentication').with_value('yes') }
        end
      end
    end
  end
end
