require 'spec_helper'

describe 'ssh::server::conf' do
  shared_examples 'it creates sshd_config with notify' do |key, value|
    it { is_expected.to contain_sshd_config(key).with_value(value) }
    it { is_expected.to contain_sshd_config(key).that_notifies(['Service[sshd]']) }
  end

  shared_examples 'it adjusts sshd_config for FIPS' do
    it { is_expected.to compile.with_all_deps }
    it { is_expected.to create_class('ssh::server::conf') }
    include_examples('it creates sshd_config with notify', 'Ciphers',
      [ 'aes256-ctr', 'aes192-ctr', 'aes128-ctr' ])

    include_examples('it creates sshd_config with notify', 'KexAlgorithms',
      [
        'ecdh-sha2-nistp521',
        'ecdh-sha2-nistp384',
        'ecdh-sha2-nistp256',
        'diffie-hellman-group-exchange-sha256',
      ])

    include_examples('it creates sshd_config with notify', 'MACs',
      [
        'hmac-sha2-256',
        'hmac-sha1',
      ])
  end

  # sshd config is dependent upon only a handful of facts that are not
  # OS-specific. So don't waste test cycles by iterating through supported
  # OSes. Just grab the first set of facts as the base facts.
  os_facts = on_supported_os.first.last

  # CentOS Versions    OpenSSH version
  # 7.0.1406           6.4
  # 7.3.1611           6.6
  # 7.4.1708-7.9.2009  7.4
  # 8.0.1905           7.8
  # 8.3.2011           8.0
  latest_openssh_version = '8.0'

  # This is a common dependency that is notified
  let(:pre_condition) { 'service { "sshd": }' }

  context 'with default parameters' do
    context 'latest openssh_version and both simp_options::fips and fips_enabled false' do
      let(:facts) { os_facts.merge({ openssh_version: latest_openssh_version, fips_enabled: false }) }

      it { is_expected.to compile.with_all_deps }
      it { is_expected.to create_class('ssh::server::conf') }
      it { is_expected.to create_file('/etc/ssh/sshd_config') }
      include_examples('it creates sshd_config with notify', 'AcceptEnv',
        [ 'LANG', 'LC_CTYPE', 'LC_NUMERIC', 'LC_TIME', 'LC_COLLATE', 'LC_MONETARY',
          'LC_MESSAGES', 'LC_PAPER', 'LC_NAME', 'LC_ADDRESS', 'LC_TELEPHONE',
          'LC_MEASUREMENT', 'LC_IDENTIFICATION', 'LC_ALL'])

      include_examples('it creates sshd_config with notify', 'AllowGroups', nil)
      include_examples('it creates sshd_config with notify', 'AllowUsers', nil)
      it { is_expected.not_to contain_sshd_config('AuthorizedKeysCommand') }
      it { is_expected.not_to contain_sshd_config('AuthorizedKeysCommandUser') }
      include_examples('it creates sshd_config with notify', 'AuthorizedKeysFile', '/etc/ssh/local_keys/%u')
      include_examples('it creates sshd_config with notify', 'Banner', '/etc/issue.net')
      include_examples('it creates sshd_config with notify', 'ChallengeResponseAuthentication', 'no')
      include_examples('it creates sshd_config with notify', 'Ciphers',
        ['aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr', 'aes192-ctr', 'aes128-ctr' ])
      include_examples('it creates sshd_config with notify', 'ClientAliveCountMax', 0)
      include_examples('it creates sshd_config with notify', 'ClientAliveInterval', 600)
      include_examples('it creates sshd_config with notify', 'Compression', 'delayed')
      include_examples('it creates sshd_config with notify', 'DenyGroups', nil)
      include_examples('it creates sshd_config with notify', 'DenyUsers', nil)
      include_examples('it creates sshd_config with notify', 'GSSAPIAuthentication', 'no')
      include_examples('it creates sshd_config with notify', 'HostbasedAuthentication', 'no')
      include_examples('it creates sshd_config with notify', 'IgnoreRhosts', 'yes')
      include_examples('it creates sshd_config with notify', 'IgnoreUserKnownHosts', 'yes')
      include_examples('it creates sshd_config with notify', 'KerberosAuthentication', 'no')
      include_examples('it creates sshd_config with notify', 'KexAlgorithms',
        [
          'curve25519-sha256@libssh.org',
          'ecdh-sha2-nistp521',
          'ecdh-sha2-nistp384',
          'ecdh-sha2-nistp256',
          'diffie-hellman-group-exchange-sha256',
        ])

      it { is_expected.not_to contain_sshd_config('ListenAddress') }
      include_examples('it creates sshd_config with notify', 'LoginGraceTime', 120)
      include_examples('it creates sshd_config with notify', 'LogLevel', nil)
      include_examples('it creates sshd_config with notify', 'MACs',
        [
          'hmac-sha2-512-etm@openssh.com',
          'hmac-sha2-256-etm@openssh.com',
          'hmac-sha2-512',
          'hmac-sha2-256',
        ])

      include_examples('it creates sshd_config with notify', 'MaxAuthTries', 6)
      include_examples('it creates sshd_config with notify', 'PasswordAuthentication', 'yes')
      include_examples('it creates sshd_config with notify', 'PermitEmptyPasswords', 'no')
      include_examples('it creates sshd_config with notify', 'PermitRootLogin', 'no')
      include_examples('it creates sshd_config with notify', 'PermitUserEnvironment', 'no')
      include_examples('it creates sshd_config with notify', 'Port', [22])
      include_examples('it creates sshd_config with notify', 'PrintLastLog', 'no')
      include_examples('it creates sshd_config with notify', 'Protocol', '2')
      it { is_expected.not_to contain_sshd_config('RhostsRSAAuthentication') }
      include_examples('it creates sshd_config with notify', 'StrictModes', 'yes')
      include_examples('it creates sshd_config with notify', 'SyslogFacility', 'AUTHPRIV')
      include_examples('it creates sshd_config with notify', 'UsePAM', 'yes')
      include_examples('it creates sshd_config with notify', 'X11Forwarding', 'no')
      it { is_expected.to contain_sshd_config('UsePrivilegeSeparation').with_ensure('absent') }
      it {
        is_expected.to contain_sshd_config_subsystem('sftp')
          .with_command('/usr/libexec/openssh/sftp-server')
      }

      it { is_expected.to create_file('/etc/ssh/local_keys') }

      it { is_expected.not_to contain_class('haveged') }
      it { is_expected.not_to contain_class('oath') }
      it { is_expected.not_to contain_file('/etc/pam.d/sshd') }
      it { is_expected.not_to contain_class('iptables') }
      it { is_expected.not_to contain_class('tcpwrappers') }
    end

    context 'latest openssh_version and only simp_options::fips true' do
      let(:facts) { os_facts.merge({ openssh_version: latest_openssh_version, fips_enabled: false }) }
      let(:hieradata) { 'fips_catalyst_enabled' }

      include_examples 'it adjusts sshd_config for FIPS'
    end

    context 'latest openssh_version and only fips_enabled false' do
      let(:facts) { os_facts.merge({ openssh_version: latest_openssh_version, fips_enabled: true }) }

      include_examples 'it adjusts sshd_config for FIPS'
    end

    context 'latest openssh_version and connected to an IPA domain' do
      let(:facts) { os_facts.merge({ openssh_version: latest_openssh_version, ipa: {} }) }

      it { is_expected.to compile.with_all_deps }
      it { is_expected.to contain_sshd_config('GSSAPIAuthentication').with_value('yes') }
    end

    # early EL7 support
    context 'openssh_version=6.4 and both simp_options::fips and fips_enabled false' do
      let(:facts) { os_facts.merge({ openssh_version: '6.4', fips_enabled: false }) }

      it { is_expected.to compile.with_all_deps }
      it { is_expected.to create_class('ssh::server::conf') }
      include_examples('it creates sshd_config with notify', 'KexAlgorithms',
        [
          'ecdh-sha2-nistp521',
          'ecdh-sha2-nistp384',
          'ecdh-sha2-nistp256',
          'diffie-hellman-group-exchange-sha256',
        ])
    end

    # early EL7 support
    context 'openssh_version=6.5 and both simp_options::fips and fips_enabled false' do
      let(:facts) { os_facts.merge({ openssh_version: '6.5', fips_enabled: false }) }

      it { is_expected.to compile.with_all_deps }
      it { is_expected.to create_class('ssh::server::conf') }
      include_examples('it creates sshd_config with notify', 'KexAlgorithms',
        [
          'curve25519-sha256@libssh.org',
          'ecdh-sha2-nistp521',
          'ecdh-sha2-nistp384',
          'ecdh-sha2-nistp256',
          'diffie-hellman-group-exchange-sha256',
        ])
    end

    # early EL7 support
    context 'openssh_version=6.6' do
      let(:facts) { os_facts.merge({ openssh_version: '6.6' }) }

      it { is_expected.to compile.with_all_deps }
      it { is_expected.to create_class('ssh::server::conf') }
      include_examples('it creates sshd_config with notify', 'RhostsRSAAuthentication', 'no')
    end

    # EL7 support
    context 'openssh_version=7.4' do
      let(:facts) { os_facts.merge({ openssh_version: '7.4' }) }

      it { is_expected.to compile.with_all_deps }
      it { is_expected.to create_class('ssh::server::conf') }
      it { is_expected.not_to contain_sshd_config('RhostsRSAAuthentication') }
      include_examples('it creates sshd_config with notify', 'UsePrivilegeSeparation', 'sandbox')
    end

    # early EL 8.0 support
    context 'openssh_version=7.8' do
      # logic checks for < 7.5, but 7.5 didn't make it into a CentOS release
      let(:facts) { os_facts.merge({ openssh_version: '7.8' }) }

      it { is_expected.to compile.with_all_deps }
      it { is_expected.to contain_sshd_config('UsePrivilegeSeparation').with_ensure('absent') }
    end
  end

  context 'with latest ssh_version and custom parameters' do
    let(:facts) { os_facts.merge({ openssh_version: latest_openssh_version }) }

    # Contexts below **loosely** follow the ordering of the code legs as they
    # appear in the manifests.

    context 'with pki enabled' do
      let(:params) { { pki: 'simp' } }

      it { is_expected.to compile.with_all_deps }
      it {
        is_expected.to contain_pki__copy('sshd').with(
        source: '/etc/pki/simp/x509',
        pki: 'simp',
      )
      }
    end

    context 'when ldap=true and sssd=true' do
      let(:params) { { ldap: true, sssd: true } }

      it { is_expected.to compile.with_all_deps }
      it { is_expected.to contain_package('sssd-common') }
      include_examples('it creates sshd_config with notify', 'AuthorizedKeysCommand', '/usr/bin/sss_ssh_authorizedkeys')
      include_examples('it creates sshd_config with notify', 'AuthorizedKeysCommandUser', 'nobody')
    end

    context 'when ldap=true and sssd=false' do
      let(:params) { { ldap: true, sssd: false } }

      it { is_expected.to compile.with_all_deps }
      it { is_expected.not_to contain_package('sssd-common') }
      include_examples('it creates sshd_config with notify', 'AuthorizedKeysCommand', '/usr/libexec/openssh/ssh-ldap-wrapper')
      include_examples('it creates sshd_config with notify', 'AuthorizedKeysCommandUser', 'nobody')
    end

    context 'with macs set' do
      context 'with macs not empty' do
        let(:params) { { macs: ['hmac-sha2-256'] } }

        it { is_expected.to compile.with_all_deps }
        include_examples('it creates sshd_config with notify', 'MACs', ['hmac-sha2-256'])
      end

      context 'with macs empty' do
        let(:params) { { macs: [] } }

        it { is_expected.to compile.with_all_deps }
        include_examples('it creates sshd_config with notify', 'MACs',
          [
            'hmac-sha2-512-etm@openssh.com',
            'hmac-sha2-256-etm@openssh.com',
            'hmac-sha2-512',
            'hmac-sha2-256',
          ])
      end
    end

    context 'with multiple protocols set' do
      let(:params) { { protocol: [2, 1] } }

      include_examples('it creates sshd_config with notify', 'Protocol', '2,1')
    end

    context 'with ciphers set' do
      context 'with ciphers not empty' do
        let(:params) { { ciphers: ['aes256-gcm@openssh.com'] } }

        it { is_expected.to compile.with_all_deps }
        include_examples('it creates sshd_config with notify', 'Ciphers',
          ['aes256-gcm@openssh.com', 'aes256-ctr', 'aes192-ctr', 'aes128-ctr' ])
      end

      context 'with ciphers empty' do
        let(:params) { { ciphers: [] } }

        it { is_expected.to compile.with_all_deps }
        include_examples('it creates sshd_config with notify', 'Ciphers',
          ['aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr', 'aes192-ctr', 'aes128-ctr' ])
      end
    end

    context 'with enable_fallback_ciphers=false' do
      let(:params) do
        {
          enable_fallback_ciphers: false,
       # set ciphers so can see that merge is not done
       ciphers: [ 'aes256-gcm@openssh.com']
        }
      end

      it { is_expected.to compile.with_all_deps }
      it { is_expected.to contain_sshd_config('Ciphers').with_value(['aes256-gcm@openssh.com']) }
    end

    context 'with kex_algorithms set' do
      context 'with kex_algorithms not empty' do
        let(:params) { { kex_algorithms: ['ecdh-sha2-nistp521'] } }

        it { is_expected.to compile.with_all_deps }
        include_examples('it creates sshd_config with notify', 'KexAlgorithms',
          ['ecdh-sha2-nistp521'])
      end

      context 'with kex_algorithms empty' do
        let(:params) { { kex_algorithms: [] } }

        it { is_expected.to compile.with_all_deps }
        include_examples('it creates sshd_config with notify', 'KexAlgorithms',
          [
            'curve25519-sha256@libssh.org',
            'ecdh-sha2-nistp521',
            'ecdh-sha2-nistp384',
            'ecdh-sha2-nistp256',
            'diffie-hellman-group-exchange-sha256',
          ])
      end
    end

    context 'with oath=true' do
      context 'with defaults' do
        let(:params) { { oath: true } }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('oath') }
        it {
          is_expected.to contain_file('/etc/pam.d/sshd').with(
          ensure: 'file',
          content: <<~EOM,
            #%PAM-1.0
            auth       required     pam_sepermit.so
            auth       [success=3 default=ignore] pam_listfile.so item=group sense=allow file=/etc/liboath/exclude_groups.oath
            auth       [success=2 default=ignore] pam_listfile.so item=user sense=allow file=/etc/liboath/exclude_users.oath
            auth       [success=1 default=bad]    pam_oath.so usersfile=/etc/liboath/users.oath window=1
            auth       requisite    pam_deny.so
            auth       substack     password-auth
            auth       include      postlogin
            # Used with polkit to reauthorize users in remote sessions
            -auth      optional     pam_reauthorize.so prepare
            account    required     pam_nologin.so
            account    include      password-auth
            password   include      password-auth
            # pam_selinux.so close should be the first session rule
            session    required     pam_selinux.so close
            session    required     pam_loginuid.so
            # pam_selinux.so open should only be followed by sessions to be executed in the user context
            session    required     pam_selinux.so open env_params
            session    required     pam_namespace.so
            session    optional     pam_keyinit.so force revoke
            session    include      password-auth
            session    include      postlogin
            # Used with polkit to reauthorize users in remote sessions
            -session   optional     pam_reauthorize.so prepare
          EOM
        )
        }

        include_examples('it creates sshd_config with notify', 'ChallengeResponseAuthentication', 'yes')
        include_examples('it creates sshd_config with notify', 'PasswordAuthentication', 'no')
      end

      context 'with usepam=false' do
        let(:params) { { oath: true, usepam: false } }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('oath') }
        it { is_expected.to contain_file('/etc/pam.d/sshd') }
        include_examples('it creates sshd_config with notify', 'UsePAM', 'yes')
      end

      context 'with manage_pam_sshd=false' do
        let(:params) { { oath: true, manage_pam_sshd: false } }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('oath') }
        it { is_expected.not_to contain_file('/etc/pam.d/sshd') }
      end
    end

    context 'with manage_pam_sshd=true' do
      context 'with defaults' do
        let(:params) { { manage_pam_sshd: true } }

        it { is_expected.to compile.with_all_deps }
        it {
          is_expected.to contain_file('/etc/pam.d/sshd').with_content(<<~EOM,
            #%PAM-1.0
            auth       required     pam_sepermit.so
            auth       substack     password-auth
            auth       include      postlogin
            # Used with polkit to reauthorize users in remote sessions
            -auth      optional     pam_reauthorize.so prepare
            account    required     pam_nologin.so
            account    include      password-auth
            password   include      password-auth
            # pam_selinux.so close should be the first session rule
            session    required     pam_selinux.so close
            session    required     pam_loginuid.so
            # pam_selinux.so open should only be followed by sessions to be executed in the user context
            session    required     pam_selinux.so open env_params
            session    required     pam_namespace.so
            session    optional     pam_keyinit.so force revoke
            session    include      password-auth
            session    include      postlogin
            # Used with polkit to reauthorize users in remote sessions
            -session   optional     pam_reauthorize.so prepare
          EOM
                                                                     )
        }
      end

      context 'with usepam=false' do
        let(:params) { { manage_pam_sshd: true, usepam: false } }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.not_to contain_file('/etc/pam.d/sshd') }
      end
    end

    context 'with authorizedkeyscommand set' do
      context 'with authorizedkeyscommanduser not empty' do
        let(:params) { { authorizedkeyscommand: '/some/command' } }

        it { is_expected.to compile.with_all_deps }
        include_examples('it creates sshd_config with notify', 'AuthorizedKeysCommand', '/some/command')
        include_examples('it creates sshd_config with notify', 'AuthorizedKeysCommandUser', 'nobody')
      end

      context 'with authorizedkeyscommanduser empty' do
        let(:params) do
          {
            authorizedkeyscommand: '/some/command',
         authorizedkeyscommanduser: ''
          }
        end

        it { is_expected.not_to compile.with_all_deps }
      end
    end

    context 'with ensure_ssd_packages_set to a Boolean' do
      context 'with ensure_sssd_packages = true' do
        let(:params) { { sssd: true, ensure_sssd_packages: true } }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_package('sssd-common') }
      end

      context 'with ensure_sssd_packages = false' do
        let(:params) { { sssd: true, ensure_sssd_packages: false } }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.not_to contain_package('sssd-common') }
      end
    end

    context 'with both simp_options::ldap and simp_options::ssd true' do
      let(:hieradata) { 'ldap_and_sssd' }

      it { is_expected.to compile.with_all_deps }
      it { is_expected.to contain_package('sssd-common') }
      it { is_expected.to contain_sshd_config('AuthorizedKeysCommand').with_value('/usr/bin/sss_ssh_authorizedkeys') }
      it { is_expected.to contain_sshd_config('AuthorizedKeysCommandUser').with_value('nobody') }
    end

    context 'with simp_options::ldap = true, but simp_options::sssd = false' do
      let(:hieradata) { 'ldap_only' }

      it { is_expected.to compile.with_all_deps }
      it { is_expected.not_to contain_package('sssd-common') }
      it { is_expected.to contain_sshd_config('AuthorizedKeysCommand').with_value('/usr/libexec/openssh/ssh-ldap-wrapper') }
      it { is_expected.to contain_sshd_config('AuthorizedKeysCommandUser').with_value('nobody') }
    end

    context 'with firewall, haveged, pam, and tcpwrappers global catalysts enabled' do
      let(:hieradata) { 'some_global_catalysts_enabled' }

      it { is_expected.to compile.with_all_deps }
      include_examples('it creates sshd_config with notify', 'UsePAM', 'yes')
      it { is_expected.to contain_class('iptables') }
      it { is_expected.to contain_iptables__listen__tcp_stateful('allow_sshd').with_dports([22]) }
      it { is_expected.to contain_class('tcpwrappers') }
      it { is_expected.to contain_tcpwrappers__allow('sshd') }
      it { is_expected.to contain_class('haveged') }
    end

    context 'with custom_entries set' do
      let(:hieradata) { 'custom_entries' }

      it { is_expected.to compile.with_all_deps }
      it { is_expected.to contain_sshd_config('X11UseLocalhost').with_value('no') }
      it { is_expected.to contain_sshd_config('X11MaxDisplays').with_value(20) }
    end

    context 'with selinux_enforced=true' do
      let(:facts) do
        os_facts.merge({
                         openssh_version: latest_openssh_version,
          selinux_enforced: true
                       })
        os_facts[:selinux] = true
        os_facts[:os][:selinux][:config_mode] = 'enforcing'
        os_facts[:os][:selinux][:config_policy] = 'targeted'
        os_facts[:os][:selinux][:current_mode] = 'enforcing'
        os_facts[:os][:selinux][:enabled] = true
        os_facts[:os][:selinux][:enforced] = true
        os_facts
      end

      context 'with a non-standard ssh port' do
        let(:params) { { port: 22_000 } }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('vox_selinux') }

        it {
          is_expected.to contain_selinux_port("tcp_#{params[:port]}-#{params[:port]}").with(
          {
            low_port: params[:port],
            high_port: params[:port],
            seltype: 'ssh_port_t',
            protocol: 'tcp'
          },
        )
        }

        it { is_expected.to contain_selinux_port("tcp_#{params[:port]}-#{params[:port]}") }
      end

      context 'with multiple SSH ports' do
        let(:params) { { port: [22_000, 22, 22_222] } }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.not_to contain_selinux_port("tcp_#{params[:port][1]}-#{params[:port][1]}") }

        it {
          is_expected.to contain_selinux_port("tcp_#{params[:port].first}-#{params[:port].first}").with(
          {
            low_port: params[:port].first,
            high_port: params[:port].first,
            seltype: 'ssh_port_t',
            protocol: 'tcp'
          },
        )
        }

        it {
          is_expected.to contain_selinux_port("tcp_#{params[:port].last}-#{params[:port].last}").with(
          {
            low_port: params[:port].last,
            high_port: params[:port].last,
            seltype: 'ssh_port_t',
            protocol: 'tcp'
          },
        )
        }
      end
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

    context 'with listenaddress set' do
      let(:params) { { listenaddress: '1.2.3.4' } }

      it { is_expected.to compile.with_all_deps }
      include_examples('it creates sshd_config with notify', 'ListenAddress', '1.2.3.4')
    end
  end

  # EL7 support
  context 'with useprivilegeseparation set to a boolean and openssh_version=7.4' do
    let(:facts) { os_facts.merge({ openssh_version: '7.4' }) }

    context '=> true' do
      let(:params) { { useprivilegeseparation: true } }

      include_examples('it creates sshd_config with notify', 'UsePrivilegeSeparation', 'yes')
    end

    context '=> false' do
      let(:params) { { useprivilegeseparation: false } }

      include_examples('it creates sshd_config with notify', 'UsePrivilegeSeparation', 'no')
    end
  end

  # EL7 support
  context 'with rhostsrsaauthentication explicitly disabled, openssh_version=7.4' do
    let(:facts) { os_facts.merge({ openssh_version: '7.4' }) }
    let(:params) { { rhostsrsaauthentication: false } }

    it { is_expected.to compile.with_all_deps }
    include_examples('it creates sshd_config with notify', 'RhostsRSAAuthentication', 'no')
  end
end
