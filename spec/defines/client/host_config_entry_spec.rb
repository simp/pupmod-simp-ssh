require 'spec_helper'

describe 'ssh::client::host_config_entry' do
  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|

      context "on #{os}" do
        let(:title) {'new_run'}

        context 'default parameters for ssh::client::host_config_entry and ssh::client, both ssh::client::fips and fips_enabled false' do
          let(:facts) do
            os_facts.merge({ :fips_enabled => false })
          end
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_class('ssh::client') }
          it { is_expected.to contain_class('ssh::client::params') }

          it {
            if (['RedHat', 'CentOS'].include?(facts[:os][:name])) and
              (facts[:os][:release][:major].to_s >= '7')
              expected_macs = ['hmac-sha2-512-etm@openssh.com',
                'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512', 'hmac-sha2-256']
              expected_ciphers = ['aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr', 'aes192-ctr', 'aes128-ctr']
            else
              expected_macs = ['hmac-sha1']
              expected_ciphers = ['aes256-ctr', 'aes192-ctr', 'aes128-ctr']
            end

            is_expected.to contain_ssh_config('new_run__AddressFamily').with_host('new_run')
            is_expected.to contain_ssh_config('new_run__AddressFamily').with_value('any')
            is_expected.to contain_ssh_config('new_run__Protocol').with_value('2')
            is_expected.to contain_ssh_config('new_run__BatchMode').with_value('no')
            is_expected.to contain_ssh_config('new_run__ChallengeResponseAuthentication').with_value('yes')
            is_expected.to contain_ssh_config('new_run__CheckHostIP').with_value('yes')
            is_expected.to contain_ssh_config('new_run__Ciphers').with_value(expected_ciphers)
            is_expected.to contain_ssh_config('new_run__ClearAllForwardings').with_value('no')
            is_expected.to contain_ssh_config('new_run__Compression').with_value('yes')
            is_expected.to contain_ssh_config('new_run__CompressionLevel').with_value('6')
            is_expected.to contain_ssh_config('new_run__ConnectionAttempts').with_value('1')
            is_expected.to contain_ssh_config('new_run__ConnectTimeout').with_value('0')
            is_expected.to contain_ssh_config('new_run__ControlMaster').with_value('no')
            is_expected.to contain_ssh_config('new_run__EnableSSHKeysign').with_value('no')
            is_expected.to contain_ssh_config('new_run__EscapeChar').with_value('~')
            is_expected.to contain_ssh_config('new_run__ExitOnForwardFailure').with_value('no')
            is_expected.to contain_ssh_config('new_run__ForwardAgent').with_value('no')
            is_expected.to contain_ssh_config('new_run__ForwardX11').with_value('no')
            is_expected.to contain_ssh_config('new_run__ForwardX11Trusted').with_value('no')
            is_expected.to contain_ssh_config('new_run__GatewayPorts').with_value('no')
            is_expected.to contain_ssh_config('new_run__GSSAPIAuthentication').with_value('no')
            is_expected.to contain_ssh_config('new_run__GSSAPIKeyExchange').with_value('no')
            is_expected.to contain_ssh_config('new_run__GSSAPIDelegateCredentials').with_value('no')
            is_expected.to contain_ssh_config('new_run__GSSAPIRenewalForcesRekey').with_value('no')
            is_expected.to contain_ssh_config('new_run__GSSAPITrustDns').with_value('no')
            is_expected.to contain_ssh_config('new_run__HashKnownHosts').with_value('yes')
            is_expected.to contain_ssh_config('new_run__HostbasedAuthentication').with_value('no')
            is_expected.to contain_ssh_config('new_run__HostKeyAlgorithms').with_value(['ssh-rsa','ssh-dss'])
            is_expected.to contain_ssh_config('new_run__IdentitiesOnly').with_value('no')
            is_expected.to contain_ssh_config('new_run__KbdInteractiveAuthentication').with_value('yes')
            is_expected.to contain_ssh_config('new_run__LogLevel').with_value('INFO')
            is_expected.to contain_ssh_config('new_run__MACs').with_value(expected_macs)
            is_expected.to contain_ssh_config('new_run__NoHostAuthenticationForLocalhost').with_value('no')
            is_expected.to contain_ssh_config('new_run__NumberOfPasswordPrompts').with_value('3')
            is_expected.to contain_ssh_config('new_run__PasswordAuthentication').with_value('yes')
            is_expected.to contain_ssh_config('new_run__PermitLocalCommand').with_value('no')
            is_expected.to contain_ssh_config('new_run__Port').with_value('22')
            is_expected.to contain_ssh_config('new_run__PreferredAuthentications').with_value('publickey,hostbased,keyboard-interactive,password')
            is_expected.to contain_ssh_config('new_run__PubkeyAuthentication').with_value('yes')
            is_expected.to contain_ssh_config('new_run__RhostsRSAAuthentication').with_value('no')
            is_expected.to contain_ssh_config('new_run__RSAAuthentication').with_value('yes')
            is_expected.to contain_ssh_config('new_run__SendEnv').with_value(['LANG','LC_CTYPE','LC_NUMERIC','LC_TIME','LC_COLLATE','LC_MONETARY','LC_MESSAGES','LC_PAPER','LC_NAME', 'LC_ADDRESS', 'LC_TELEPHONE', 'LC_MEASUREMENT', 'LC_IDENTIFICATION' ,'LC_ALL'])
            is_expected.to contain_ssh_config('new_run__ServerAliveCountMax').with_value('3')
            is_expected.to contain_ssh_config('new_run__ServerAliveInterval').with_value('0')
            is_expected.to contain_ssh_config('new_run__StrictHostKeyChecking').with_value('ask')
            is_expected.to contain_ssh_config('new_run__TCPKeepAlive').with_value('yes')
            is_expected.to contain_ssh_config('new_run__Tunnel').with_value('yes')
            is_expected.to contain_ssh_config('new_run__UsePrivilegedPort').with_value('no')
            is_expected.to contain_ssh_config('new_run__VerifyHostKeyDNS').with_value('no')
            is_expected.to contain_ssh_config('new_run__VisualHostKey').with_value('no')
            is_expected.to contain_ssh_config('new_run__XAuthLocation').with_value('/usr/bin/xauth')
          }

          context 'when connected to an IPA domain' do
            let(:facts) {
              super().merge!(
                ipa: {
                  domain: 'test.local',
                  server: 'ipaserver.test.local'
                }
              )
            }
            it { is_expected.to compile.with_all_deps }
            it 'should enable GSSAPIAuthentication' do
              is_expected.to contain_ssh_config('new_run__GSSAPIAuthentication').with_value('yes')
            end
          end
          context 'when connected to an IPA domain and GSSAPIAuthentication is set to false' do
            let(:params) {{ gssapiauthentication: false }}
            let(:facts) {
              super().merge!(
                ipa: {
                  domain: 'test.local',
                  server: 'ipaserver.test.local'
                }
              )
            }
            it { is_expected.to compile.with_all_deps }
            it 'should enable GSSAPIAuthentication' do
              is_expected.to contain_ssh_config('new_run__GSSAPIAuthentication').with_value('yes')
            end
          end
        end

        context 'with optional parameters specified, both ssh::client::fips and fips_enabled false' do
          let(:facts) do
            os_facts.merge({ :fips_enabled => false })
          end
          let(:params) {{
            :bindaddress           => '1.2.3.4',
            :ciphers               => ['aes128-ctr', 'aes192-ctr'],
            :controlpath           => '/some/control/path',
            :dynamicforward        => '1.2.3.4:1022',
            :globalknownhostsfile  => ['/some/hosts/file1', '/some/hosts/file2'],
            :hostkeyalias          => 'some.alias',
            :hostname              => 'some.hostname',
            :identityfile          => '/some/identity/file',
            :kbdinteractivedevices => ['bsdauth','pam'],
            :localcommand          => 'some --local --command %d',
            :localforward          => '2223 3.4.5.6:2235',
            :macs                  => ['hmac-sha2-256','hmac-sha2-512'],
            :proxycommand          => '/usr/bin/nc -X connect -x 192.0.2.0:8080 %h %p',
            :rekeylimit            => '5G',
            :remoteforward         => '3334 4.5.6.7:3345',
            :smartcarddevice       => 'dev_sc',
            :tunneldevice          => 'dev_td',
            :user                  => 'bob',
            :userknownhostsfile    => ['/some/hosts/file3', '/some/hosts/file4']
          }}
          it { is_expected.to compile.with_all_deps }
          it {
            is_expected.to contain_ssh_config('new_run__AddressFamily').with_value('any')
            is_expected.to contain_ssh_config('new_run__Protocol').with_value('2')
            is_expected.to contain_ssh_config('new_run__BatchMode').with_value('no')
            is_expected.to contain_ssh_config('new_run__ChallengeResponseAuthentication').with_value('yes')
            is_expected.to contain_ssh_config('new_run__CheckHostIP').with_value('yes')
            is_expected.to contain_ssh_config('new_run__Ciphers').with_value(['aes128-ctr','aes192-ctr'])
            is_expected.to contain_ssh_config('new_run__ClearAllForwardings').with_value('no')
            is_expected.to contain_ssh_config('new_run__Compression').with_value('yes')
            is_expected.to contain_ssh_config('new_run__CompressionLevel').with_value('6')
            is_expected.to contain_ssh_config('new_run__ConnectionAttempts').with_value('1')
            is_expected.to contain_ssh_config('new_run__ConnectTimeout').with_value('0')
            is_expected.to contain_ssh_config('new_run__ControlMaster').with_value('no')
            is_expected.to contain_ssh_config('new_run__EnableSSHKeysign').with_value('no')
            is_expected.to contain_ssh_config('new_run__EscapeChar').with_value('~')
            is_expected.to contain_ssh_config('new_run__ExitOnForwardFailure').with_value('no')
            is_expected.to contain_ssh_config('new_run__ForwardAgent').with_value('no')
            is_expected.to contain_ssh_config('new_run__ForwardX11').with_value('no')
            is_expected.to contain_ssh_config('new_run__ForwardX11Trusted').with_value('no')
            is_expected.to contain_ssh_config('new_run__GatewayPorts').with_value('no')
            is_expected.to contain_ssh_config('new_run__GSSAPIAuthentication').with_value('no')
            is_expected.to contain_ssh_config('new_run__GSSAPIKeyExchange').with_value('no')
            is_expected.to contain_ssh_config('new_run__GSSAPIDelegateCredentials').with_value('no')
            is_expected.to contain_ssh_config('new_run__GSSAPIRenewalForcesRekey').with_value('no')
            is_expected.to contain_ssh_config('new_run__GSSAPITrustDns').with_value('no')
            is_expected.to contain_ssh_config('new_run__HashKnownHosts').with_value('yes')
            is_expected.to contain_ssh_config('new_run__HostbasedAuthentication').with_value('no')
            is_expected.to contain_ssh_config('new_run__HostKeyAlgorithms').with_value(['ssh-rsa','ssh-dss'])
            is_expected.to contain_ssh_config('new_run__IdentitiesOnly').with_value('no')
            is_expected.to contain_ssh_config('new_run__KbdInteractiveAuthentication').with_value('yes')
            is_expected.to contain_ssh_config('new_run__LogLevel').with_value('INFO')
            is_expected.to contain_ssh_config('new_run__MACs').with_value(['hmac-sha2-256','hmac-sha2-512'])
            is_expected.to contain_ssh_config('new_run__NoHostAuthenticationForLocalhost').with_value('no')
            is_expected.to contain_ssh_config('new_run__NumberOfPasswordPrompts').with_value('3')
            is_expected.to contain_ssh_config('new_run__PasswordAuthentication').with_value('yes')
            is_expected.to contain_ssh_config('new_run__PermitLocalCommand').with_value('no')
            is_expected.to contain_ssh_config('new_run__Port').with_value('22')
            is_expected.to contain_ssh_config('new_run__PreferredAuthentications').with_value('publickey,hostbased,keyboard-interactive,password')
            is_expected.to contain_ssh_config('new_run__PubkeyAuthentication').with_value('yes')
            is_expected.to contain_ssh_config('new_run__RhostsRSAAuthentication').with_value('no')
            is_expected.to contain_ssh_config('new_run__RSAAuthentication').with_value('yes')
            is_expected.to contain_ssh_config('new_run__SendEnv').with_value(['LANG','LC_CTYPE','LC_NUMERIC','LC_TIME','LC_COLLATE','LC_MONETARY','LC_MESSAGES','LC_PAPER','LC_NAME', 'LC_ADDRESS', 'LC_TELEPHONE', 'LC_MEASUREMENT', 'LC_IDENTIFICATION' ,'LC_ALL'])
            is_expected.to contain_ssh_config('new_run__ServerAliveCountMax').with_value('3')
            is_expected.to contain_ssh_config('new_run__ServerAliveInterval').with_value('0')
            is_expected.to contain_ssh_config('new_run__StrictHostKeyChecking').with_value('ask')
            is_expected.to contain_ssh_config('new_run__TCPKeepAlive').with_value('yes')
            is_expected.to contain_ssh_config('new_run__Tunnel').with_value('yes')
            is_expected.to contain_ssh_config('new_run__UsePrivilegedPort').with_value('no')
            is_expected.to contain_ssh_config('new_run__VerifyHostKeyDNS').with_value('no')
            is_expected.to contain_ssh_config('new_run__VisualHostKey').with_value('no')
            is_expected.to contain_ssh_config('new_run__XAuthLocation').with_value('/usr/bin/xauth')
            is_expected.to contain_ssh_config('new_run__BindAddress').with_value('1.2.3.4')
            is_expected.to contain_ssh_config('new_run__ControlPath').with_value('/some/control/path')
            is_expected.to contain_ssh_config('new_run__DynamicForward').with_value('1.2.3.4:1022')
            is_expected.to contain_ssh_config('new_run__GlobalKnownHostsFile').with_value('/some/hosts/file1 /some/hosts/file2')
            is_expected.to contain_ssh_config('new_run__HostKeyAlias').with_value('some.alias')
            is_expected.to contain_ssh_config('new_run__HostName').with_value('some.hostname')
            is_expected.to contain_ssh_config('new_run__IdentityFile').with_value('/some/identity/file')
            is_expected.to contain_ssh_config('new_run__KbdInteractiveDevices').with_value('bsdauth,pam')
            is_expected.to contain_ssh_config('new_run__LocalCommand').with_value('some --local --command %d')
            is_expected.to contain_ssh_config('new_run__LocalForward').with_value('2223 3.4.5.6:2235')
            is_expected.to contain_ssh_config('new_run__ProxyCommand').with_value('/usr/bin/nc -X connect -x 192.0.2.0:8080 %h %p')
            is_expected.to contain_ssh_config('new_run__RekeyLimit').with_value('5G')
            is_expected.to contain_ssh_config('new_run__RemoteForward').with_value('3334 4.5.6.7:3345')
            is_expected.to contain_ssh_config('new_run__SmartcardDevice').with_value('dev_sc')
            is_expected.to contain_ssh_config('new_run__TunnelDevice').with_value('dev_td')
            is_expected.to contain_ssh_config('new_run__User').with_value('bob')
            is_expected.to contain_ssh_config('new_run__UserKnownHostsFile').with_value('/some/hosts/file3 /some/hosts/file4')
          }

        end

        _protocol_sets = [
          1,
          '2,1'
       ]
        _protocol_sets.each do |_protocol_set|
          context "with protocol = #{_protocol_set} and both ssh::client::fips and fips_enabled false" do
            let(:facts) do
              os_facts.merge({ :fips_enabled => false })
            end
            let(:params){{ :protocol => _protocol_set }}

            it { is_expected.to compile.with_all_deps }
            it {
              is_expected.to contain_ssh_config('new_run__Protocol').with_value(%r[#{_protocol_set}])
              is_expected.to contain_ssh_config('new_run__Cipher').with_value('3des')
            }
          end
        end

        _protocol_sets = [
          1,
          2,
          '2,1'
       ]
        _protocol_sets.each do |_protocol_set|
          context "with protocol = #{_protocol_set}, simp_options::fips = false, and fips_enabled = true" do
            let(:facts){  os_facts.merge({ :fips_enabled => true }) }
            let(:params){{ :protocol => _protocol_set }}

            it {
              if (['RedHat', 'CentOS'].include?(facts[:os][:name])) and
                (facts[:os][:release][:major].to_s >= '7')
                expected_macs = ['hmac-sha2-256', 'hmac-sha1']
                expected_ciphers = ['aes256-ctr', 'aes192-ctr', 'aes128-ctr']
              else
                expected_macs = ['hmac-sha1']
                expected_ciphers = ['aes256-ctr', 'aes192-ctr', 'aes128-ctr']
              end

              is_expected.to contain_ssh_config('new_run__Protocol').with_value('2')
              is_expected.not_to contain_ssh_config('new_run__Cipher')
              is_expected.to contain_ssh_config('new_run__MACs').with_value(expected_macs)
              is_expected.to contain_ssh_config('new_run__Ciphers').with_value(expected_ciphers)
            }
          end
        end

        _protocol_sets.each do |_protocol_set|
          context "with protocol = #{_protocol_set}, simp_options::fips = true, and fips_enabled = false" do
            let(:facts){  os_facts.merge({ :fips_enabled => false }) }
            let(:params){{ :protocol => _protocol_set }}
            let(:hieradata) {'global_catalysts_enabled'}

            it { is_expected.to compile.with_all_deps }
            it {
              if (['RedHat', 'CentOS'].include?(facts[:os][:name])) and
                (facts[:os][:release][:major].to_s >= '7')
                expected_macs = ['hmac-sha2-256', 'hmac-sha1']
                expected_ciphers = ['aes256-ctr', 'aes192-ctr', 'aes128-ctr']
              else
                expected_macs = ['hmac-sha1']
                expected_ciphers = ['aes256-ctr', 'aes192-ctr', 'aes128-ctr']
              end

              is_expected.to contain_ssh_config('new_run__Protocol').with_value('2')
              is_expected.not_to contain_ssh_config('new_run__Cipher')
              is_expected.to contain_ssh_config('new_run__MACs').with_value(expected_macs)
              is_expected.to contain_ssh_config('new_run__Ciphers').with_value(expected_ciphers)
            }
          end
        end
      end
    end
  end
end
