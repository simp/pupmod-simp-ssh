require 'spec_helper'

describe 'ssh::client::host_config_entry' do
  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|

      context "on #{os}" do
        let(:title) {'new_run'}

        context 'default parameters for ssh::client::host_config_entry and ssh::client, both ssh::client::fips and fips_enabled false' do
          let(:facts) do
            os_facts.merge({:fips_enabled => false})
          end
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_class('ssh::client') }
          it { is_expected.to contain_class('ssh::client::params') }

          it {
            if (['RedHat', 'CentOS'].include?(facts[:os][:name])) and
              (facts[:os][:release][:major].to_s >= '7')
              expected_macs = [ 'hmac-sha2-512-etm@openssh.com',
                'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512', 'hmac-sha2-256' ]
              expected_ciphers = [ 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr', 'aes192-ctr', 'aes128-ctr' ]
            else
              expected_macs = [ 'hmac-sha1' ]
              expected_ciphers = [ 'aes256-ctr', 'aes192-ctr', 'aes128-ctr' ]
            end

            is_expected.to contain_concat__fragment('ssh_config_new_run').with_content(<<EOM
Host new_run
    AddressFamily any
    Protocol 2
    BatchMode no
    ChallengeResponseAuthentication yes
    CheckHostIP yes
    Ciphers #{expected_ciphers.join(',')}
    ClearAllForwardings no
    Compression yes
    CompressionLevel 6
    ConnectionAttempts 1
    ConnectTimeout 0
    ControlMaster no
    EnableSSHKeysign no
    EscapeChar ~
    ExitOnForwardFailure no
    ForwardAgent no
    ForwardX11 no
    ForwardX11Trusted no
    GatewayPorts no
    GSSAPIAuthentication no
    GSSAPIKeyExchange no
    GSSAPIDelegateCredentials no
    GSSAPIRenewalForcesRekey no
    GSSAPITrustDns no
    HashKnownHosts yes
    HostbasedAuthentication no
    HostKeyAlgorithms ssh-rsa,ssh-dss
    IdentitiesOnly no
    KbdInteractiveAuthentication yes
    LogLevel INFO
    MACs #{expected_macs.join(',')}
    NoHostAuthenticationForLocalhost no
    NumberOfPasswordPrompts 3
    PasswordAuthentication yes
    PermitLocalCommand no
    Port 22
    PreferredAuthentications publickey,hostbased,keyboard-interactive,password
    PubkeyAuthentication yes
    RhostsRSAAuthentication no
    RSAAuthentication yes
    SendEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT LC_IDENTIFICATION LC_ALL
    ServerAliveCountMax 3
    ServerAliveInterval 0
    StrictHostKeyChecking ask
    TCPKeepAlive yes
    Tunnel yes
    UsePrivilegedPort no
    VerifyHostKeyDNS no
    VisualHostKey no
    XAuthLocation /usr/bin/xauth
EOM
            )
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
              is_expected.to contain_concat__fragment('ssh_config_new_run').with_content(
                %r(GSSAPIAuthentication yes)
              )
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
              is_expected.to contain_concat__fragment('ssh_config_new_run').with_content(
                %r(GSSAPIAuthentication yes)
              )
            end
          end
        end

        context 'with optional parameters specified, both ssh::client::fips and fips_enabled false' do
          let(:facts) do
            os_facts.merge({:fips_enabled => false})
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
            is_expected.to contain_concat__fragment('ssh_config_new_run').with_content(<<EOM
Host new_run
    AddressFamily any
    Protocol 2
    BatchMode no
    ChallengeResponseAuthentication yes
    CheckHostIP yes
    Ciphers aes128-ctr,aes192-ctr
    ClearAllForwardings no
    Compression yes
    CompressionLevel 6
    ConnectionAttempts 1
    ConnectTimeout 0
    ControlMaster no
    EnableSSHKeysign no
    EscapeChar ~
    ExitOnForwardFailure no
    ForwardAgent no
    ForwardX11 no
    ForwardX11Trusted no
    GatewayPorts no
    GSSAPIAuthentication no
    GSSAPIKeyExchange no
    GSSAPIDelegateCredentials no
    GSSAPIRenewalForcesRekey no
    GSSAPITrustDns no
    HashKnownHosts yes
    HostbasedAuthentication no
    HostKeyAlgorithms ssh-rsa,ssh-dss
    IdentitiesOnly no
    KbdInteractiveAuthentication yes
    LogLevel INFO
    MACs hmac-sha2-256,hmac-sha2-512
    NoHostAuthenticationForLocalhost no
    NumberOfPasswordPrompts 3
    PasswordAuthentication yes
    PermitLocalCommand no
    Port 22
    PreferredAuthentications publickey,hostbased,keyboard-interactive,password
    PubkeyAuthentication yes
    RhostsRSAAuthentication no
    RSAAuthentication yes
    SendEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT LC_IDENTIFICATION LC_ALL
    ServerAliveCountMax 3
    ServerAliveInterval 0
    StrictHostKeyChecking ask
    TCPKeepAlive yes
    Tunnel yes
    UsePrivilegedPort no
    VerifyHostKeyDNS no
    VisualHostKey no
    XAuthLocation /usr/bin/xauth
    BindAddress 1.2.3.4
    ControlPath /some/control/path
    DynamicForward 1.2.3.4:1022
    GlobalKnownHostsFile /some/hosts/file1 /some/hosts/file2
    HostKeyAlias some.alias
    HostName some.hostname
    IdentityFile /some/identity/file
    KbdInteractiveDevices bsdauth,pam
    LocalCommand some --local --command %d
    LocalForward 2223 3.4.5.6:2235
    ProxyCommand /usr/bin/nc -X connect -x 192.0.2.0:8080 %h %p
    RekeyLimit 5G
    RemoteForward 3334 4.5.6.7:3345
    SmartcardDevice dev_sc
    TunnelDevice dev_td
    User bob
    UserKnownHostsFile /some/hosts/file3 /some/hosts/file4
EOM
            )
          }

        end

        _protocol_sets = [
          1,
          '2,1'
        ]
        _protocol_sets.each do |_protocol_set|
          context "with protocol = #{_protocol_set} and both ssh::client::fips and fips_enabled false" do
            let(:facts) do
              os_facts.merge({:fips_enabled => false})
            end
            let(:params){{ :protocol => _protocol_set }}

            it { is_expected.to compile.with_all_deps }
            it {
              is_expected.to contain_concat__fragment('ssh_config_new_run').with_content(
                %r(Protocol #{_protocol_set}$)
              )
              is_expected.to contain_concat__fragment('ssh_config_new_run').with_content(
                %r(Cipher 3des$)
              )
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
                expected_macs = [ 'hmac-sha2-256', 'hmac-sha1']
                expected_ciphers = [ 'aes256-ctr', 'aes192-ctr', 'aes128-ctr' ]
              else
                expected_macs = [ 'hmac-sha1' ]
                expected_ciphers = [ 'aes256-ctr', 'aes192-ctr', 'aes128-ctr' ]
              end

              is_expected.to contain_concat__fragment('ssh_config_new_run').with_content(
                %r(Protocol 2$)
              )
              is_expected.to contain_concat__fragment('ssh_config_new_run').without_content(
                %r(Cipher )
              )

              is_expected.to contain_concat__fragment('ssh_config_new_run').with_content(
                %r(MACs #{expected_macs.join(',')}$)
              )
              is_expected.to contain_concat__fragment('ssh_config_new_run').with_content(
                %r(Ciphers #{expected_ciphers.join(',')}$)
              )
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
                expected_macs = [ 'hmac-sha2-256', 'hmac-sha1']
                expected_ciphers = [ 'aes256-ctr', 'aes192-ctr', 'aes128-ctr' ]
              else
                expected_macs = [ 'hmac-sha1' ]
                expected_ciphers = [ 'aes256-ctr', 'aes192-ctr', 'aes128-ctr' ]
              end

              is_expected.to contain_concat__fragment('ssh_config_new_run').with_content(
                %r(Protocol 2$)
              )
              is_expected.to contain_concat__fragment('ssh_config_new_run').without_content(
                %r(Cipher )
              )

              is_expected.to contain_concat__fragment('ssh_config_new_run').with_content(
                %r(MACs #{expected_macs.join(',')}$)
              )
              is_expected.to contain_concat__fragment('ssh_config_new_run').with_content(
                %r(Ciphers #{expected_ciphers.join(',')}$)
              )
            }
          end
        end
      end
    end
  end
end
