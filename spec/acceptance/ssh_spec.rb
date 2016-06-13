require 'spec_helper_acceptance'

test_name 'ssh class'

describe 'ssh class' do
  let(:server_manifest) {
    <<-EOS
      class { 'ssh::server':
         use_simp_pki => false,
      }
    EOS
  }
  let(:server_hieradata) {{
    'client_nets'                        => ['ALL'],
    'use_fips'                           => false,
    'use_ldap'                           => false,
    'use_sssd'                           => false,
    'use_tcpwrappers'                    => false,
    'use_iptables'                       => false,
    'ssh::server::conf::banner'          => '/dev/null',
    'ssh::server::conf::permitrootlogin' => true,
  }}

  let(:client_manifest) {
    <<-EOS
      include 'ssh::client'
    EOS
  }

  ['el7','el6'].each do |os|
    context "on #{os}:" do
      let(:server){ only_host_with_role( hosts, "#{os}-server" ) }
      let(:client){ only_host_with_role( hosts, "#{os}-client" ) }

      context 'with disabled SIMP features' do
        it 'should configure server with no errors' do
          install_package(server, 'epel-release')
          install_package(client, 'epel-release')
          set_hieradata_on(server, server_hieradata)
          # the ssh module needs to be run 3 times before it stops making changes
          # see SIMP-1143
          apply_manifest_on(server, server_manifest, :expect_changes => true)
          apply_manifest_on(server, server_manifest, :acceptable_exit_codes => [0,2]) # allow for 0-many changes
          apply_manifest_on(server, server_manifest, :acceptable_exit_codes => [0,2])
        end
        it "should configure #{os}-server idempotently" do
          set_hieradata_on(server, server_hieradata)
          apply_manifest_on(server, server_manifest, :catch_changes => true)
        end

        it "should configure #{os}-client with no errors" do
          apply_manifest_on(client, client_manifest, :expect_changes => true)
        end
        it "should configure #{os}-client idempotently" do
          apply_manifest_on(client, client_manifest, :catch_changes => true)
        end
      end

      context 'logging into machines as root' do
        it 'should be able to ssh into localhost' do
          install_package(server, 'expect')
          install_package(client, 'expect')
          scp_to(hosts, './spec/acceptance/files/ssh_test_script', '/tmp/ssh_test_script')
          on(hosts, "chmod +x /tmp/ssh_test_script")

          on(server, "/tmp/ssh_test_script root localhost puppet")
        end

        it "should be able to ssh into #{os}-client" do
          on(client, "/tmp/ssh_test_script root #{os}-server puppet")
        end
      end

      context 'with a test user' do
        it 'should be able to log in with password' do
          #create a test user and set a password
          on(hosts, 'useradd testuser', :accept_all_exit_codes => true)
          on(hosts, 'echo password | passwd testuser --stdin')

          on(client, "/tmp/ssh_test_script testuser #{os}-server password")
        end

        it 'should be able to log in with just a key' do
          # copy the key to local_keys
          scp_to(server, './spec/acceptance/files/id_rsa_pub.example', '/etc/ssh/local_keys/testuser')
          on(server, 'chmod o+r /etc/ssh/local_keys/testuser')
          on(client, "su testuser -c 'mkdir /home/testuser/.ssh'")
          scp_to(client, './spec/acceptance/files/id_rsa_pub.example', '/home/testuser/.ssh/id_rsa.pub')
          scp_to(client, './spec/acceptance/files/id_rsa.example', '/home/testuser/.ssh/id_rsa')
          on(client, 'chown -R testuser:testuser /home/testuser')

          on(client, "ssh -o StrictHostKeyChecking=no -i ~testuser/.ssh/id_rsa testuser@#{os}-server echo Logged in successfully")
        end

        it 'should not accept old ciphers when not enabled' do
          new_hieradata = server_hieradata.merge( { 'ssh::server::conf::enable_fallback_ciphers' => false } )
          set_hieradata_on(server, new_hieradata)
          apply_manifest_on(server, server_manifest)

          if (fact_on(server, 'operatingsystem') == 'CentOS' and fact_on(server, 'operatingsystemmajrelease') == '6') then
            on(client, "ssh -o StrictHostKeyChecking=no -o Ciphers=3des-cbc -i ~testuser/.ssh/id_rsa testuser@#{os}-server echo Logged in successfully", :acceptable_exit_codes => [255])
          else
            on(client, "ssh -o StrictHostKeyChecking=no -o Ciphers=aes128-cbc,aes192-cbc,aes256-cbc -i ~testuser/.ssh/id_rsa testuser@#{os}-server echo Logged in successfully", :acceptable_exit_codes => [255])
          end
        end

        it 'should prompt user to change password if expired and logging in with cert' do
          # reset and expire testuser password
          on(hosts, 'echo password | passwd testuser --stdin')
          on(hosts, 'chage -d 0 testuser')
          scp_to(hosts, './spec/acceptance/files/ssh_test_script_change_pass', '/tmp/ssh_test_script_change_pass')
          on(hosts, "chmod +x /tmp/ssh_test_script_change_pass")

          on(client, "/tmp/ssh_test_script_change_pass testuser #{os}-server password correcthorsebatterystaple")
          on(client, "/tmp/ssh_test_script testuser #{os}-server correcthorsebatterystaple")
        end

        it 'should prompt user to change password if expired' do
          # reset and expire testuser password
          on(hosts, 'echo password | passwd testuser --stdin')
          on(hosts, 'chage -d 0 testuser')
          # remove publc key from server
          on(server, 'rm -rf /etc/ssh/local_keys/*')

          on(client, "/tmp/ssh_test_script_change_pass testuser #{os}-server password correcthorsebatterystaple")
          on(client, "/tmp/ssh_test_script testuser #{os}-server correcthorsebatterystaple")
        end

      end
    end
  end

  context 'on el7:' do
    let(:server){ only_host_with_role( hosts, 'el6-server' ) }
    let(:client){ only_host_with_role( hosts, 'el7-client' ) }

    it 'should be able to connect to el6' do
      new_hieradata = server_hieradata.merge( { 'ssh::server::conf::enable_fallback_ciphers' => true } )
      set_hieradata_on(server, new_hieradata)
      apply_manifest_on(server, server_manifest, :acceptable_exit_codes => [0,2])
      apply_manifest_on(client, client_manifest, :acceptable_exit_codes => [0,2])

      require 'pry';binding.pry
      on(client, "/tmp/ssh_test_script testuser el6-server password", :accept_all_exit_codes => true)
    end

    context 'with enable_fallback_ciphers = false' do
      it 'should be able to connect to el6,' do
        new_hieradata = server_hieradata.merge( { 'ssh::server::conf::enable_fallback_ciphers' => false } )
        set_hieradata_on(server, new_hieradata)
        apply_manifest_on(server, server_manifest, :acceptable_exit_codes => [0,2])
        apply_manifest_on(client, client_manifest, :acceptable_exit_codes => [0,2])

        require 'pry';binding.pry
        on(client, "/tmp/ssh_test_script testuser el6-server password", :accept_all_exit_codes => true)
      end
    end
  end

  context 'on el6:' do
    let(:server){ only_host_with_role( hosts, 'el7-server' ) }
    let(:client){ only_host_with_role( hosts, 'el6-client' ) }

    it 'should be able to connect to el7' do
      new_hieradata = server_hieradata.merge( { 'ssh::server::conf::enable_fallback_ciphers' => true } )
      set_hieradata_on(server, new_hieradata)
      apply_manifest_on(server, server_manifest, :acceptable_exit_codes => [0,2])
      apply_manifest_on(client, client_manifest, :acceptable_exit_codes => [0,2])

      require 'pry';binding.pry
      on(client, "/tmp/ssh_test_script testuser el7-server password", :accept_all_exit_codes => true)
    end

    context 'with enable_fallback_ciphers = false,' do
      it 'should be able to connect to el7' do
        new_hieradata = server_hieradata.merge( { 'ssh::server::conf::enable_fallback_ciphers' => false } )
        set_hieradata_on(server, new_hieradata)
        apply_manifest_on(server, server_manifest, :acceptable_exit_codes => [0,2])
        apply_manifest_on(client, client_manifest, :acceptable_exit_codes => [0,2])

        require 'pry';binding.pry
        on(client, "/tmp/ssh_test_script testuser el7-server password", :accept_all_exit_codes => true)
      end
    end
  end

end
