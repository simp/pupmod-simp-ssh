require 'spec_helper_acceptance'
require 'json'

test_name 'ssh check oath'

describe 'ssh check oath' do
  let(:client_hieradata) { { 'simp_options::oath' => false } }

  let(:server_hieradata) do
    {
      'simp_options::trusted_nets'            => ['ALL'],
      'simp_options::oath'                    => true,
      'simp_options::pam'                     => true,
      # 9.0.0 removed the simp_options seams from ssh::server::conf, so the
      # simp_options::oath key above no longer reaches the ssh module (it is
      # kept for the oath module itself); opt in to OATH management directly.
      'ssh::server::conf::oath'               => true,
      # Opt in to service management so sshd reloads to pick up the
      # OATH-driven KbdInteractive/PasswordAuthentication settings.
      'ssh::server::service_ensure'           => 'running',
      'ssh::server::service_enable'           => true,
      'ssh::server::conf::banner'             => '/dev/null',
      'ssh::server::conf::permitrootlogin'    => true,
      'ssh::server::conf::authorizedkeysfile' => '.ssh/authorized_keys',
      'pam::access::users'                    => JSON.parse(%({ "defaults": { "origins": [ "ALL" ], "permission": "+" }, "vagrant": null, "root": null, "testuser": null, "tst0_usr": null })),
      'oath::oath_users'                      => JSON.parse(%({"tst0_usr": {"token_type": "HOTP/T30/6", "pin": "-", "secret_key": "000001"}})),
    }
  end

  #
  # NOTE: by default, include 'ssh' will automatically include the ssh_server
  let(:client_manifest) do
    <<~CLIENT_CONFIG
      include 'ssh::client'
      include 'oath'
    CLIENT_CONFIG
  end

  let(:server_manifest) do
    <<~SERVER_CONFIG
      include 'ssh::server'
      include 'oath'
      include 'pam'
    SERVER_CONFIG
  end
  let(:password) { 'suP3rF00B@rB@11bx23' }

  let(:files_dir) { File.join(File.dirname(__FILE__), 'files') }

  hosts_as('server').each do |sut_server|
    os = sut_server.hostname.split('-').first
    context "on #{os}:" do
      let(:server) { sut_server }

      let(:client) do
        os = server.hostname.split('-').first
        hosts_as('client').find { |x| x.hostname =~ %r{^#{os}-.+} }
      end

      context 'with default parameters' do
        it 'configures server with no errors' do
          enable_epel_on(client)
          install_package(client, 'expect')

          set_hieradata_on(client, client_hieradata)
          apply_manifest_on(client, client_manifest, expect_changes: true)

          set_hieradata_on(server, server_hieradata)
          apply_manifest_on(server, server_manifest, expect_changes: true)
          # Work around a bug in augeasproviders_ssh
          apply_manifest_on(server, server_manifest, catch_failures: true)
        end

        it "configures #{os}-server idempotently" do
          set_hieradata_on(server, server_hieradata)
          apply_manifest_on(server, server_manifest, catch_changes: true)
        end

        it "configures #{os}-client idempotently" do
          apply_manifest_on(client, client_manifest, catch_changes: true)
        end
      end

      context 'server needs a test user with passwd' do
        let(:test_user) { 'tst0_usr' }

        it 'add test user' do
          on(server, "puppet resource user #{test_user} ensure=present comment='Tst0 User'")
          stdin = "#{password}\n" * 2
          on(server, "passwd #{test_user} ", stdin: stdin)
        end
      end

      context 'Test /etc/pam.d/sshd oath through ssh' do
        let(:test_user) { 'tst0_usr' }
        let(:oath_key) { '000001' }
        let(:bad_oath_key) { '1337' }
        let(:bad_password) { 'h4x0r' }

        before(:each) do
          # The live OATH-over-SSH login exercises the pam_oath
          # keyboard-interactive PAM stack. That runtime path does not engage
          # reliably under a container runtime (rootless podman + seccomp in CI
          # is even stricter), so sshd never offers keyboard-interactive and
          # these logins cannot be validated. The OATH *configuration* (manifest
          # apply, idempotency and the PAM/sshd files) is still verified above;
          # we only skip the live login assertions under docker, leaving them
          # active on a full-VM hypervisor.
          if hosts.any? { |h| h[:hypervisor] == 'docker' }
            skip 'OATH keyboard-interactive PAM login is not supported under a container runtime'
          end
        end

        it 'Copy test scripts to server' do
          scp_to(client, File.join(files_dir, 'ssh_test_script'), '/usr/local/bin/ssh_test_script')
          on(client, 'chmod u+x /usr/local/bin/ssh_test_script')
          scp_to(client, File.join(files_dir, 'oath_ssh_test_script'), '/usr/local/bin/oath_ssh_test_script')
          on(client, 'chmod u+x /usr/local/bin/oath_ssh_test_script')
        end

        it 'check that the test user can ssh' do
          # This example is pending on every currently supported EL release, for
          # two distinct reasons:
          #
          # EL8/EL9: a live OATH login over SSH is rejected even though the OATH
          # configuration is correct and the full /etc/pam.d/sshd stack accepts
          # the same token when driven directly (verified via pamtester): the
          # token delivered through sshd's keyboard-interactive channel is not
          # accepted (users.oath never records it).
          # See https://github.com/simp/pupmod-simp-ssh/issues/222
          #
          # EL10: pam_oath cannot create its lock file. pam_oath >= 2.6.12 (the
          # CVE-2024-47191 rework) takes a lock at /var/lock/pam_oath.lock
          # before updating the usersfile, and fails the authentication if it
          # cannot. OpenSSH 9.9 runs each session -- including the PAM auth
          # conversation -- as sshd-session, which the EL10 policy confines in
          # the new sshd_session_t domain. sshd_t still carries
          # `allow sshd_t var_lock_t:dir { add_name remove_name write }` and the
          # matching file rules, but sshd_session_t was never given them, so the
          # create is denied:
          #
          #   avc: denied { write } for comm="sshd-session" name="lock"
          #        scontext=...:sshd_session_t tcontext=...:var_lock_t tclass=dir
          #
          # Confirmed on AlmaLinux 10 (selinux-policy 42.1.18-4.el10_2.3,
          # openssh 9.9p1-25, pam_oath 2.6.12-1): the login succeeds under
          # `setenforce 0`, and under enforcing once pam_oath is pointed at a
          # lock file the login domain may write. This is an selinux-policy
          # regression in the sshd-session domain split, not a module defect --
          # nothing in this module or in vox_selinux changed. The durable fix
          # belongs on the pam_oath side (mutable OATH state and its lock
          # relabelled into /var/lib, where the login_pgm attribute already
          # grants full var_auth_t management); it is deferred until after the
          # blast-radius refactor in #220 lands.
          # See https://github.com/simp/pupmod-simp-ssh/issues/235
          if fact_on(server, 'os.release.major').to_i <= 9
            pending('OATH keyboard-interactive login over SSH fails on EL8/EL9 (see issue #222)')
          else
            pending('pam_oath cannot create /var/lock/pam_oath.lock from sshd_session_t on EL10 (see issue #235)')
          end
          on(client, "/usr/local/bin/oath_ssh_test_script #{test_user} #{oath_key} #{password} #{os}-server")
        end

        it 'fail auth with bad TOTP' do
          on(client, "/usr/local/bin/oath_ssh_test_script #{test_user} #{bad_oath_key} #{password} #{os}-server", acceptable_exit_codes: [1])
        end

        it 'fail auth with good TOTP and bad pass' do
          on(client, "/usr/local/bin/oath_ssh_test_script #{test_user} #{oath_key} #{bad_password} #{os}-server", acceptable_exit_codes: [1])
        end

        it 'test user exclusion' do
          on(server, "echo '#{test_user}' >> /etc/liboath/exclude_users.oath")
          on(client, "/usr/local/bin/ssh_test_script #{test_user} #{os}-server #{password}")
          # Clean up test_user out of exclude_users file
          on(server, "echo 'vagrant' > /etc/liboath/exclude_users.oath")
          on(server, "echo 'root' >> /etc/liboath/exclude_users.oath")
        end

        it 'test group exclusion' do
          on(server, 'groupadd test_group')
          on(server, "echo 'test_group' >> /etc/liboath/exclude_groups.oath")
          on(server, "usermod -aG test_group #{test_user}")
          on(client, "/usr/local/bin/ssh_test_script #{test_user} #{os}-server #{password}")
          # Clean up test_user out of exclude_groups file
          on(server, "echo '' > /etc/liboath/exclude_groups.oath")
        end
      end
    end
  end
end
