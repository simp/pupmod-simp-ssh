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
    id_rsa = %q(-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
)
    id_rsa_pub = %q(ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDI9DPUsQXNTqU2nWShmMCnGOXPDYazX4yHFrI7Xw3p/r62Li6zaSSNuJ8varX24j8NNMK9EeYcQnrkEu+PE7kO7UTnat3AQFASAlnZTkqo4F/bQjoVEvVaZHaAupiiQYMJny+8R/0VrPGQGx3IR2ORuMs0nAZjjZK3pdmMNNi284Rox3qi9qCeQY0yO3sdyygRwtKyAJvOSwTVrTuYQrMVzWbWsbBk7wO27A7bwbaCZ/nZFzjwB+t3HTJ2t9ZSxCtH0tnvPUEtswZdVN+yAKwka8dyULvhnGtfc8wcA8OJoYmb5Sqh67QU+ofBRkj1I0F33VfEyrNME9q5jT0V2/uS5WJjUNPScBZeZjR60ZA791ZrmyAw9ybK55h8SNmZWi3/PyteaZnHVY4fe0M38MtHy2qh+vBp2o/aVIhGo/cWotQpZaPMnJeNzqlvNQXm04Rz+5BeOZBAOLH/TiJFXpEoNYLYPSy7p1Y22QKPoMmgjp5MiCvBhY1v60rHnogBOTor5rebD2R+KyVK6beLb/nABCoJNvquefE+fpo/5+zVr9IfCDnnTJLKtUuNetk6D0gl76bhsfiEsWz2r1ND7ihXjcv3z3v38V4mr8m3cmAuVU7mNYHZvwM5i55VNitS1qUiSkvccKBbnxa15e0YxXUfnq8PI/Yq2Iky/K4am/XMkw== testuser@server)


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
