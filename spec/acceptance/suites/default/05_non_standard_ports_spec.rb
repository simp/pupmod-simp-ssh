require 'spec_helper_acceptance'
require_relative '../../support/lib/helpers/dump_sshd_ciphers'

test_name 'ssh non-standard ports'

describe 'ssh class' do
  target_ports = [22, 2222, 22_222]

  let(:server_manifest) { "include 'ssh::server'" }

  let(:server_hieradata) do
    {
      'simp_options::trusted_nets'                => ['ALL'],
      'simp_options::firewall'                    => true,
      'ssh::server::conf::banner'                 => '/dev/null',
      'ssh::server::conf::permitrootlogin'        => true,
      'ssh::server::conf::passwordauthentication' => true,
      'ssh::server::conf::port' => target_ports
    }
  end

  let(:files_dir) { File.join(File.dirname(__FILE__), 'files') }

  hosts_as('server').each do |sut_server|
    os = sut_server.hostname.split('-').first
    context "on #{os}:" do
      let(:server) { sut_server }

      let(:client) do
        os = server.hostname.split('-').first
        hosts_as('client').find { |x| x.hostname =~ %r{^#{os}-.+} }
      end

      it 'configures server with no errors' do
        set_hieradata_on(server, server_hieradata)
        apply_manifest_on(server, server_manifest, expect_changes: true)
      end

      it "configures #{os}-server idempotently" do
        apply_manifest_on(server, server_manifest, catch_changes: true)
      end

      it 'creates a user for the test' do
        # create a test user and set a password
        on(hosts, 'useradd non_standard_user', accept_all_exit_codes: true)
        on(hosts, 'echo password | passwd non_standard_user --stdin')
      end

      it 'is able to log in with just a key' do
        # copy the key to local_keys
        scp_to(server, File.join(files_dir, 'id_rsa_pub.example'), '/etc/ssh/local_keys/non_standard_user')
        on(server, 'chmod o+r /etc/ssh/local_keys/non_standard_user')

        on(client, "su non_standard_user -c 'mkdir /home/non_standard_user/.ssh'")
        scp_to(client, File.join(files_dir, 'id_rsa_pub.example'), '/home/non_standard_user/.ssh/id_rsa.pub')
        scp_to(client, File.join(files_dir, 'id_rsa.example'), '/home/non_standard_user/.ssh/id_rsa')
        on(client, 'chown -R non_standard_user:non_standard_user /home/non_standard_user')
      end

      target_ports.each do |port|
        context "using port #{port}" do
          let(:ssh_cmd) do
            "ssh -p #{port} -o StrictHostKeyChecking=no -i ~non_standard_user/.ssh/id_rsa non_standard_user@#{os}-server"
          end

          it "is able to log in via port #{port}" do
            on(client, "#{ssh_cmd} echo Logged in successfully")
          end
        end
      end
    end
  end
end
