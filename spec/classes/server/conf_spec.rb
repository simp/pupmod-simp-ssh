require 'spec_helper'

describe 'ssh::server::conf' do

  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      let(:facts) do
        os_facts
      end

      context "on os #{os}" do
        # This is a common dependency that is notified
        let(:pre_condition){ 'service { "sshd": }' }

        context 'with default parameters' do
          context 'openssh_version=5.3, both simp_options::fips and fips_enabled false' do
            let(:facts) { os_facts.merge( { :openssh_version => '5.3', :fips_enabled => false } ) }

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

            expected_ciphers = ['aes256-gcm@openssh.com', 'aes128-gcm@openssh.com',
                                'aes256-ctr', 'aes192-ctr', 'aes128-ctr' ]
            expected_macs = [ 'hmac-sha2-512-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com',
             'hmac-sha2-512', 'hmac-sha2-256' ]
            is_expected.to contain_sshd_config('UsePrivilegeSeparation').with_value('sandbox')

            is_expected.to contain_sshd_config('Ciphers').with_value(expected_ciphers)
            is_expected.to contain_sshd_config('MACs').with_value(expected_macs)

            }
            it { is_expected.to contain_sshd_config('Compression').with_value('delayed') }
            it { is_expected.to contain_sshd_config('ClientAliveCountMax').with_value(0) }
            it { is_expected.to contain_sshd_config('ClientAliveInterval').with_value(600) }
            it { is_expected.to contain_sshd_config('SyslogFacility').with_value('AUTHPRIV') }
            it { is_expected.to contain_sshd_config('GSSAPIAuthentication').with_value('no') }
            it { is_expected.to contain_sshd_config('HostbasedAuthentication').with_value('no') }
            it { is_expected.to contain_sshd_config('IgnoreRhosts').with_value('yes') }
            it { is_expected.to contain_sshd_config('IgnoreUserKnownHosts').with_value('yes') }
            it { is_expected.to contain_sshd_config('KerberosAuthentication').with_value('no') }
            it { is_expected.to_not contain_sshd_config('KexAlgorithms') }
            it { is_expected.to contain_sshd_config('Port').with_value([22]) }
            it { is_expected.to contain_sshd_config('PermitEmptyPasswords').with_value('no') }
            it { is_expected.to contain_sshd_config('PermitRootLogin').with_value('no') }
            it { is_expected.to contain_sshd_config('PermitUserEnvironment').with_value('no') }
            it { is_expected.to contain_sshd_config('PrintLastLog').with_value('no') }
            it { is_expected.to contain_sshd_config('RhostsRSAAuthentication').with_value('no') }
            it { is_expected.to contain_sshd_config('StrictModes').with_value('yes') }
            it { is_expected.to contain_sshd_config('UsePAM').with_value('yes') }
            it { is_expected.to contain_sshd_config('X11Forwarding').with_value('no') }
            it { is_expected.to_not contain_sshd_config('AuthorizedKeysCommand') }
            it { is_expected.to_not contain_sshd_config('AuthorizedKeysCommandUser') }
            it { is_expected.to create_file('/etc/ssh/local_keys') }
            it { is_expected.to_not contain_class('iptables') }
            it { is_expected.to_not contain_class('tcpwrappers') }
            it { is_expected.to_not contain_class('haveged') }
          end

          context 'openssh_version=6.6, both simp_options::fips and fips_enabled false' do
            let(:facts) { os_facts.merge( { :openssh_version => '6.6', :fips_enabled => false } ) }

            it { is_expected.to compile.with_all_deps }
            it {
              expected_ciphers = [ 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr',
               'aes192-ctr', 'aes128-ctr' ]

              expected_macs = [ 'hmac-sha2-512-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com',
               'hmac-sha2-512', 'hmac-sha2-256' ]

              expected_kex_algorithms = [ 'curve25519-sha256@libssh.org', 'ecdh-sha2-nistp521',
                'ecdh-sha2-nistp384', 'ecdh-sha2-nistp256', 'diffie-hellman-group-exchange-sha256']

              is_expected.to contain_sshd_config('Ciphers').with_value(expected_ciphers)
              is_expected.to contain_sshd_config('MACs').with_value(expected_macs)
              is_expected.to contain_sshd_config('KexAlgorithms').with_value(expected_kex_algorithms)
            }
          end

          context 'openssh_version=5.3, simp_options::fips=true and fips_enabled=false' do
            let(:facts) { os_facts.merge( { :openssh_version => '5.3', :fips_enabled => false } ) }
            let(:hieradata) { 'fips_catalyst_enabled' }

            # Force cache invalidation
            let(:params) {{ :app_pki_external_source => 'fips_catalyst_enabled' }}

            it { is_expected.to compile }
            it {
              expected_ciphers = [ 'aes256-ctr', 'aes192-ctr', 'aes128-ctr' ]
              expected_macs = [ 'hmac-sha2-256', 'hmac-sha1' ]

              is_expected.to contain_sshd_config('Ciphers').with_value(expected_ciphers)
              is_expected.to contain_sshd_config('MACs').with_value(expected_macs)
            }
            it { is_expected.to_not contain_sshd_config('KexAlgorithms') }
          end

          context 'openssh_version=6.6, simp_options::fips=false and fips_enabled=true' do
            let(:facts) { os_facts.merge( { :openssh_version => '6.6', :fips_enabled => true } ) }

            it { is_expected.to compile.with_all_deps }
            it {
              expected_ciphers = [ 'aes256-ctr', 'aes192-ctr', 'aes128-ctr' ]

              expected_macs = [ 'hmac-sha2-256', 'hmac-sha1' ]

              expected_kex_algorithms = [ 'ecdh-sha2-nistp521', 'ecdh-sha2-nistp384',
                'ecdh-sha2-nistp256', 'diffie-hellman-group-exchange-sha256']

              is_expected.to contain_sshd_config('Ciphers').with_value(expected_ciphers)
              is_expected.to contain_sshd_config('MACs').with_value(expected_macs)
              is_expected.to contain_sshd_config('KexAlgorithms').with_value(expected_kex_algorithms)
            }
          end

          context 'openssh_version=7.5' do
            let(:facts) { os_facts.merge( { :openssh_version => '7.5' } ) }

            it { is_expected.to compile.with_all_deps }
            it { is_expected.to contain_sshd_config('UsePrivilegeSeparation').with_ensure('absent') }
          end
        end

        context 'with manage_pam_sshd=true' do
          let(:facts) { os_facts.merge( { :openssh_version => '7.4'} ) }
          let(:params) {{ :manage_pam_sshd => true }}

          it { is_expected.to compile.with_all_deps }
        end

        context 'with enable_fallback_ciphers=false' do
          let(:facts) { os_facts.merge( { :openssh_version => '6.6', :fips_enabled => false } ) }
          let(:hieradata) { 'enable_fallback_ciphers_disabled' }

          it { is_expected.to compile.with_all_deps }
          it {
            expected_ciphers = ['aes256-gcm@openssh.com', 'aes128-gcm@openssh.com',
                                'aes256-ctr', 'aes192-ctr', 'aes128-ctr' ]
            is_expected.to contain_sshd_config('Ciphers').with_value(expected_ciphers)
          }
        end

        context 'with permitrootlogin set' do
          let(:facts) { os_facts.merge( { :openssh_version => '6.6', :fips_enabled => false } ) }
          [
           true,
           false,
           'without-password',
           'forced-commands-only',
           'prohibit-password'
          ].each do |value|
            context "to #{value}" do
              let(:params) {{
                :permitrootlogin => value
              }}

              if value == true
                it { is_expected.to compile.with_all_deps }
                it { is_expected.to contain_sshd_config('PermitRootLogin').with_value('yes') }
              elsif value == false
                it { is_expected.to compile.with_all_deps }
                it { is_expected.to contain_sshd_config('PermitRootLogin').with_value('no') }
              else
                it { is_expected.to compile.with_all_deps }
                it { is_expected.to contain_sshd_config('PermitRootLogin').with_value(value) }
              end
            end
          end
        end

        context 'with authorizedkeyscommand and authorizedkeyscommanduser set' do
          let(:facts){ os_facts.merge( { :openssh_version => '6.6', :fips_enabled => true } ) }
          let(:params){{
            :authorizedkeyscommand => '/some/command'
          }}

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_sshd_config('AuthorizedKeysCommand').with_value('/some/command') }
          it { is_expected.to contain_sshd_config('AuthorizedKeysCommandUser').with_value('nobody') }
        end

        context 'with authorizedkeyscommand set but authorizedkeyscommanduser empty' do
          let(:facts) { os_facts.merge( { :openssh_version => '6.6', :fips_enabled => true } ) }
          let(:params){{
            :authorizedkeyscommand     => '/some/command',
            :authorizedkeyscommanduser => ''
          }}

          it { is_expected.to_not compile.with_all_deps }
        end

        context 'with useprivilegeseparation' do
          let(:facts) { os_facts.merge( { :openssh_version => '6.6' } ) }

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

          # Force cache invalidation
          let(:params) {{ :app_pki_external_source => 'ldap_and_sssd' }}

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_package('sssd-common') }
          it { is_expected.to contain_sshd_config('AuthorizedKeysCommand').with_value('/usr/bin/sss_ssh_authorizedkeys') }
          it { is_expected.to contain_sshd_config('AuthorizedKeysCommandUser').with_value('nobody') }
        end

        context 'with simp_options::ldap = true, but simp_options::ssd = false' do
          let(:facts) { os_facts.merge( { :openssh_version => '6.6', :fips_enabled => true } ) }
          let(:hieradata) { 'ldap_only' }

          # Force cache invalidation
          let(:params) {{ :app_pki_external_source => 'ldap_only' }}

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to_not contain_package('sssd-common') }
          it { is_expected.to contain_sshd_config('AuthorizedKeysCommand').with_value('/usr/libexec/openssh/ssh-ldap-wrapper') }
          it { is_expected.to contain_sshd_config('AuthorizedKeysCommandUser').with_value('nobody') }
        end

        context 'with firewall, haveged, pam, and tcpwrappers global catalysts enabled' do
          let(:facts) { os_facts.merge( { :openssh_version => '6.6', :fips_enabled => true } ) }
          let(:hieradata) { 'some_global_catalysts_enabled' }

          # Force cache invalidation
          let(:params) {{ :app_pki_external_source => 'some_global_catalysts_enabled' }}

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_sshd_config('UsePAM').with_value('yes') }
          it { is_expected.to contain_class('iptables') }
          it { is_expected.to contain_class('tcpwrappers') }
          it { is_expected.to contain_class('haveged') }
        end

        context 'when connected to an IPA domain' do
          let(:facts) {
            os_facts.merge(
              ipa: {}
            )
          }

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_sshd_config('GSSAPIAuthentication').with_value('yes') }
        end

        context 'with default parameters, openssh_version=7.4' do
          let(:facts) { os_facts.merge( { :openssh_version => '7.4'} ) }

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to_not contain_sshd_config('RhostsRSAAuthentication') }
        end

        context 'with rhostsrsaauthentication explicitly disabled, openssh_version=7.4' do
          let(:facts) { os_facts.merge( { :openssh_version => '7.4'} ) }
          let(:params) {{ :rhostsrsaauthentication => false }}

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_sshd_config('RhostsRSAAuthentication').with_value('no') }
        end

        context 'with custom entries' do
          let(:facts) { os_facts.merge( { :openssh_version => '7.4'} ) }
          let(:hieradata) { 'custom_entries' }

          # Force cache invalidation
          let(:params) {{ :app_pki_external_source => 'custom_entries' }}

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_sshd_config('X11UseLocalhost').with_value('no') }
          it { is_expected.to contain_sshd_config('X11MaxDisplays').with_value(20) }
        end

        context "with a non-standard ssh port" do
          let(:facts) { os_facts.merge( { :openssh_version => '7.4'} ) }
          let(:params) {{ :port => 22000 }}

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_class('vox_selinux') }

          it { is_expected.to contain_selinux_port("tcp_#{params[:port]}-#{params[:port]}").with(
            {
              :low_port  => params[:port],
              :high_port => params[:port],
              :seltype   => 'ssh_port_t',
              :protocol  => 'tcp'
            })
          }

          it { is_expected.to contain_selinux_port("tcp_#{params[:port]}-#{params[:port]}") }
        end

        context "with multiple SSH ports" do
          let(:facts) { os_facts.merge( { :openssh_version => '7.4'} ) }
          let(:params) {{ :port => [22000, 22, 22222] }}

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to_not contain_selinux_port("tcp_#{params[:port][1]}-#{params[:port][1]}") }

          it { is_expected.to contain_selinux_port("tcp_#{params[:port].first}-#{params[:port].first}").with(
            {
              :low_port  => params[:port].first,
              :high_port => params[:port].first,
              :seltype   => 'ssh_port_t',
              :protocol  => 'tcp'
            })
          }
          it { is_expected.to contain_selinux_port("tcp_#{params[:port].last}-#{params[:port].last}").with(
            {
              :low_port  => params[:port].last,
              :high_port => params[:port].last,
              :seltype   => 'ssh_port_t',
              :protocol  => 'tcp'
            })
          }
        end

        context 'with remove_entries set' do
          let(:hieradata) { 'remove_entries' }

          it { is_expected.to compile.with_all_deps }

          # entries ssh::server::conf would normally set
          it { is_expected.to contain_sshd_config('AcceptEnv').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('AllowGroups').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('AllowUsers').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('AuthorizedKeysCommand').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('AuthorizedKeysCommandUser').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('AuthorizedKeysCommand').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('AuthorizedKeysCommandUser').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('AuthorizedKeysCommand').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('AuthorizedKeysCommandUser').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('AuthorizedKeysFile').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('Banner').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('ChallengeResponseAuthentication').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('Ciphers').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('ClientAliveInterval').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('ClientAliveCountMax').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('Compression').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('DenyGroups').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('DenyUsers').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('GSSAPIAuthentication').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('HostbasedAuthentication').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('KerberosAuthentication').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('KexAlgorithms').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('IgnoreRhosts').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('IgnoreUserKnownHosts').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('ListenAddress').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('LoginGraceTime').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('LogLevel').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('MACs').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('MaxAuthTries').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('PasswordAuthentication').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('PermitEmptyPasswords').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('PermitRootLogin').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('PermitUserEnvironment').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('Port').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('PrintLastLog').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('Protocol').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('RhostsRSAAuthentication').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('StrictModes').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('SyslogFacility').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('UsePAM').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('UsePrivilegeSeparation').with_ensure('absent') }
          it { is_expected.to contain_sshd_config('X11Forwarding').with_ensure('absent') }

          # other entries
          it { is_expected.to contain_sshd_config('AuthorizedPrincipalsCommand').with_ensure('absent') }

        end

        context 'with remove_subsystems set' do
          let(:hieradata) { 'remove_subsystems' }

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_sshd_config_subsystem('imap').with_ensure('absent') }
        end
      end
    end
  end
end
