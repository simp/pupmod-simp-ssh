require 'spec_helper_acceptance'
require 'json'

test_name 'ssh check oath'

describe 'ssh check oath' do
  let(:client_hieradata) { 'simp_options::oath => false' }

  let(:server_hieradata) do
    {
      'simp_options::trusted_nets'            => ['ALL'],
      'simp_options::oath'                    => true,
      'simp_options::pam'                     => true,
      'ssh::server::conf::banner'             => '/dev/null',
      'ssh::server::conf::permitrootlogin'    => true,
      'ssh::server::conf::authorizedkeysfile' => '.ssh/authorized_keys',
      'pam::access::users'                    => JSON.parse(%Q({ "defaults": { "origins": [ "ALL" ], "permission": "+" }, "vagrant": null, "root": null, "testuser": null, "tst0_usr": null })),
      'oath::oath_users'                      => JSON.parse(%Q({"tst0_usr": {"token_type": "HOTP/T30/6", "pin": "-", "secret_key": "000001"}}))
    }
  end

  #
  # NOTE: by default, include 'ssh' will automatically include the ssh_server
  let(:client_manifest) do
    <<-CLIENT_CONFIG
         include 'ssh::client'
         include 'oath'
    CLIENT_CONFIG
  end

  let(:server_manifest) do
    <<-SERVER_CONFIG
         include 'ssh::server'
         include 'oath'
         include 'pam'
    SERVER_CONFIG
  end
  let(:password) { 'suP3rF00B@rB@11bx23' }

  let(:files_dir) { File.join(File.dirname(__FILE__), 'files') }

  hosts_as('server').each do |_server|
    os = _server.hostname.split('-').first
    context "on #{os}:" do
      let(:server) { _server }

      let(:client) do
        os = server.hostname.split('-').first
        hosts_as('client').select { |x| x.hostname =~ %r{^#{os}-.+} }.first
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

        it "should configure #{os}-server idempotently" do
          set_hieradata_on(server, server_hieradata)
          apply_manifest_on(server, server_manifest, catch_changes: true)
        end

        it "should configure #{os}-client idempotently" do
          apply_manifest_on(client, client_manifest, catch_changes: true)
        end
      end

      context 'server needs a test user with passwd' do
        let(:test_user) { 'tst0_usr' }

        it 'add test user' do
          on(server, "puppet resource user #{test_user} ensure=present comment='Tst0 User'")
          stdin = "#{password}\n" * 2
          on(server, "passwd #{test_user} ", :stdin => stdin)
        end
      end

      context 'Test /etc/pam.d/sshd oath through ssh' do
        let(:test_user) { 'tst0_usr' }
        let(:oath_key) { '000001' }
        let(:bad_oath_key) { '1337' }
        let(:bad_password) { 'h4x0r' }

        it 'Copy test scripts to server' do
          scp_to(client, File.join(files_dir, 'ssh_test_script'), '/usr/local/bin/ssh_test_script')
          on(client, 'chmod u+x /usr/local/bin/ssh_test_script')
          scp_to(client, File.join(files_dir, 'oath_ssh_test_script'), '/usr/local/bin/oath_ssh_test_script')
          on(client, 'chmod u+x /usr/local/bin/oath_ssh_test_script')
        end

        it 'check that the test user can ssh' do
          on(client, "/usr/local/bin/oath_ssh_test_script #{test_user} #{oath_key} #{password} #{os}-server")
        end

        it 'fail auth with bad TOTP' do
          on(client, "/usr/local/bin/oath_ssh_test_script #{test_user} #{bad_oath_key} #{password} #{os}-server", :acceptable_exit_codes => [1])
        end

        it 'fail auth with good TOTP and bad pass' do
          on(client, "/usr/local/bin/oath_ssh_test_script #{test_user} #{oath_key} #{bad_password} #{os}-server", :acceptable_exit_codes => [1])
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
