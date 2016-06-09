require 'spec_helper_acceptance'

test_name 'ssh class'

describe 'ssh class' do
  let(:server){ only_host_with_role( hosts, 'server' ) }
  let(:server_fqdn){ fact_on( server, 'fqdn' ) }
  let(:server_manifest) {
    <<-EOS
      class { 'ssh::server':
         use_simp_pki => false,
      }
    EOS
  }
  let(:server_hieradata) {
    {
      'client_nets'                        => ['ALL'],
      'use_fips'                           => false,
      'use_ldap'                           => false,
      'use_sssd'                           => false,
      'use_tcpwrappers'                    => false,
      'use_iptables'                       => false,
      # 'ssh::server::conf::port'            => '2222',
      'ssh::server::conf::permitrootlogin' => true,
    }
  }

  let(:client){ only_host_with_role( hosts, 'client' ) }
  let(:client_fqdn){ fact_on( client, 'fqdn' ) }
  let(:client_manifest) {
    <<-EOS
      include 'ssh::client'
    EOS
  }


  context 'with disabled SIMP features' do
    it 'should configure server with no errors' do
      set_hieradata_on(server, server_hieradata)
      # the ssh module needs to be run 3 times before it stops making changes
      # see SIMP-1143
      apply_manifest_on(server, server_manifest, :expect_changes => true)
      apply_manifest_on(server, server_manifest, :expect_changes => true)
      apply_manifest_on(server, server_manifest, :expect_changes => true)
    end
    it 'should configure server idempotently' do
      set_hieradata_on(server, server_hieradata)
      apply_manifest_on(server, server_manifest, :catch_changes => true)
    end

    it 'should configure client with no errors' do
      apply_manifest_on(client, client_manifest, :expect_changes => true)
    end
    it 'should configure client idempotently' do
      apply_manifest_on(client, client_manifest, :catch_changes => true)
    end
  end

  context 'logging into machines as root' do
    it 'should be able to ssh into localhost' do
      on(server, "/tmp/ssh_test_script root localhost puppet")
    end

    it 'should be able to ssh into client' do
      on(client, "/tmp/ssh_test_script root server puppet")
    end
  end

  context 'test user' do
    let :id_rsa do
      p File.open( File.expand_path( 'files/id_rsa.example', File.dirname(__FILE__)), 'r')
        .readlines
        .join("\n")
    end

    let :id_rsa_pub do
      File.open( File.expand_path( 'files/id_rsa_pub.example', File.dirname(__FILE__)), 'r')
        .readlines
        .join("\n")
    end



    it 'should be able to log in with password' do
      #create a test user and set a password
      on(hosts, 'useradd testuser')
      on(hosts, 'echo password | passwd testuser --stdin')

      on(client, '/tmp/ssh_test_script testuser server password')
    end

    it 'should be able to log in with just a key' do
      # copy the key to local_keys
      create_remote_file(server, '/etc/ssh/local_keys/testuser', id_rsa_pub)
      on(server, 'chown :ssh_keys /etc/ssh/local_keys/testuser; chmod o+r /etc/ssh/local_keys/testuser')
      on(client, "su testuser -c 'mkdir /home/testuser/.ssh'")
      create_remote_file(client, '/home/testuser/.ssh/id_rsa.pub', id_rsa_pub)
      create_remote_file(client, '/home/testuser/.ssh/id_rsa', id_rsa)
      on(client, 'chown -R testuser:testuser /home/testuser')

      on(client, 'ssh -o StrictHostKeyChecking=no -i ~testuser/.ssh/id_rsa testuser@server echo Logged in successfully')
    end

    it 'should not accept fallback ciphers when not enabled' do
      server_hieradata = {
        'client_nets'                        => ['ALL'],
        'use_fips'                           => false,
        'use_ldap'                           => false,
        'use_sssd'                           => false,
        'use_tcpwrappers'                    => false,
        'use_iptables'                       => false,
        'ssh::server::conf::permitrootlogin' => true,
        'ssh::server::conf::enable_fallback_ciphers' => false,
      }
      set_hieradata_on(server, server_hieradata)
      apply_manifest_on(server, server_manifest)
      apply_manifest_on(server, server_manifest)

      on(client, 'ssh -o StrictHostKeyChecking=no -o Ciphers=aes128-cbc,aes192-cbc,aes256-cbc -i ~testuser/.ssh/id_rsa testuser@server echo Logged in successfully', :acceptable_exit_codes => [255])
    end

    # make another ssh key with a password
    it 'should be able to log in with a password and key' do
      # create_remote_file(hosts, '/etc/ssh/local_keys/testuser', id_rsa_pub)
      # create_remote_file(hosts, '/home/testuser/.ssh/id_rsa', id_rsa)
      # on(hosts, 'chown :ssh_keys /etc/ssh/local_keys/testuser')
      # on(hosts, 'chown -R testuser:testuser /home/testuser')

      on(client, '/tmp/ssh_test_script testuser client password')
    end

    it 'should prompt user to change password if expired' do
      # expire testuser password
      on(hosts, 'chage -d 0 testuser')
      # remove publc key from server
      on(server, 'rm -rf /etc/ssh/local_keys/*')

      on(client, '/tmp/ssh_test_script testuser client password')
    end

  end
end
