require 'spec_helper'

shared_examples_for 'a sshkey resource generator' do |catalogue, fqdn, rsakey, ensure_val|
end

describe 'ssh::global_known_hosts' do
  let(:environment) { 'testenv' }

  on_supported_os.each do |os, os_facts|
    let(:facts) { os_facts }
    let(:rsakey1) {
      'AAAAB3NzaC1yc2EAAAADAQABAAABAQCwleF+W/kETFTKeG8TxkFwWivC/24XR3N/fAeq210bt/8Txf5uel3NQL3RkgFIvwEFcghucE9VUvk1Jtn+vr0ncKp7uNP10oXlLKeCmuUEsCPKd4L7aMg1yeITYL1imLQt0/SFaHpehKI4V+remCTVY+ccwKsCk++AL6s/cas22roh031ZkLZIkf4ipvpM2A4mBbwzwdzlx+KPgBa/YylSm5pUEmKW5er/SMrloglHs5B90f8FJ0oiHOlkLZaCJLKMUIS5zNj365ZUf/omCqeeWqT1tHqTYm6dJM2No/c6Gw+9bHTL5HRq1Al1ztSqitffD/W2ctItr1d0C7ogL2Xv'
    }

    let(:rsakey2) {
      'AAAAB3NzaC1yc2EAAAADAQABAAABAQCaD6M2c/1mvMlXU8lbsH1r87Rg3kZAJO7Or1b6ymQv6VNCzkndOTsVfG/p9ZK/bjck8+LbZVVPJ8zj/WZ508LLFgPpi7kr0gv9NYi+ZPAr8LY/n9dbHi4NmLAjyDvLfbOBgQ5SfNw+qELofSJw2eQIr8jvj2HtYuzrXs+/0T5o95zI+sfOQGOMv6q8COYv2r5GPWL0/P7Gn6GPeIicMcryx8Spt6n0QtM7RSAcUztQgwxhq1GDNTsZOKhSyu10/5wvMLxobcduESNrEDCIO2x/KrVq5lKUHg8P/Zn4RcoqgB2diEm8XeE73QKDRboPPb0HerDZtjcKysOTLD2FrFFD'
    }

    context "on #{os}" do
      context 'with default param & no pre-existing ssh_global_known_hosts dir' do
        it 'creates ssh_global_known_hosts dir, host key file and sshkey resource' do
          # Puppet[:vardir] is dynamically created as a tmpdir by the test
          # framework, when the subject is first created. So create the
          # subject now to retrieve that setting for use in our expectations
          # within this example block.
          subject()
          vardir = Puppet[:vardir]
          ssh_global_known_hosts_dir = File.join(vardir, 'simp',
            'environments', environment, 'simp_autofiles',
            'ssh_global_known_hosts')
          my_host_keyfile = File.join(ssh_global_known_hosts_dir, facts[:fqdn])

          expect(! File.exist?(ssh_global_known_hosts_dir))

          # Will create directories and this host's rsa key file
          is_expected.to run
          expect(File.exist?(ssh_global_known_hosts_dir))
          expect(File.exist?(my_host_keyfile))
          expect(IO.read(my_host_keyfile).strip).to eq facts[:sshrsakey]

          #FIXME This doesn't work in a function context
#          is_expected.to create_sshkey(facts[:fqdn])
          resource = catalogue.resource('Sshkey', facts[:fqdn])
          expect(resource).to_not be_nil

          expected_hash = {
            :type         => 'ssh-rsa',
            :host_aliases => facts[:fqdn].split('.').first,
            :key          => facts[:sshrsakey],
            :ensure       => 'present'
          }
          expect(resource.to_hash).to include(expected_hash)
        end
      end

      context 'with pre-existing ssh_global_known_hosts dir containing dups' do
        it 'removes older dup files' do
          # Puppet[:vardir] is dynamically created as a tmpdir by the test
          # framework, when the subject is first created. So create the
          # subject now to retrieve that setting for use in our expectations
          # within this example block.
          subject()
          vardir = Puppet[:vardir]
          ssh_global_known_hosts_dir = File.join(vardir, 'simp',
            'environments', environment, 'simp_autofiles',
            'ssh_global_known_hosts')
          FileUtils.mkdir_p(ssh_global_known_hosts_dir)
          short_host1_keyfile = File.join(ssh_global_known_hosts_dir, 'host1')
          long_host1_keyfile  = File.join(ssh_global_known_hosts_dir, 'host1.example.com')
          short_host2_keyfile = File.join(ssh_global_known_hosts_dir, 'host2')
          long_host2_keyfile  = File.join(ssh_global_known_hosts_dir, 'host2.example.com')

          File.open(short_host1_keyfile, 'w') { |file| file.puts(rsakey1) }
          File.open(long_host2_keyfile, 'w') { |file| file.puts(rsakey2) }
          sleep(2)
          File.open(long_host1_keyfile, 'w') { |file| file.puts(rsakey1) }
          File.open(short_host2_keyfile, 'w') { |file| file.puts(rsakey2) }

          is_expected.to run

          # Make suring running more than once is OK
          is_expected.to run

          expect(!File.exist?(short_host1_keyfile))
          expect(File.exist?(long_host1_keyfile))
          expect(File.exist?(short_host2_keyfile))
          expect(!File.exist?(long_host2_keyfile))

          #FIXME These doesn't work in a function context
#          is_expected.to create_sshkey(facts[:fqdn])
#          is_expected.to create_sshkey('host1.example.com')
#          is_expected.to create_sshkey('host2')

          [ facts[:fqdn], 'host1.example.com', 'host2'].each do |host|
            resource = catalogue.resource('Sshkey', host)
            expect(resource).to_not be_nil
            expect(resource.to_hash[:ensure]).to eq 'present'
          end
        end
      end

      context 'with pre-existing ssh_global_known_hosts dir containing old keys' do
        it 'removes old key files and creates sshkey resources with ensure absent' do
          # Puppet[:vardir] is dynamically created as a tmpdir by the test
          # framework, when the subject is first created. So create the
          # subject now to retrieve that setting for use in our expectations
          # within this example block.
          subject()
          vardir = Puppet[:vardir]
          ssh_global_known_hosts_dir = File.join(vardir, 'simp',
            'environments', environment, 'simp_autofiles',
            'ssh_global_known_hosts')
          FileUtils.mkdir_p(ssh_global_known_hosts_dir)
          old_host1_keyfile = File.join(ssh_global_known_hosts_dir, 'host1.example.com')
          old_host2_keyfile = File.join(ssh_global_known_hosts_dir, 'host2.example.com')

          File.open(old_host1_keyfile, 'w') { |file| file.puts(rsakey1) }
          File.open(old_host2_keyfile, 'w') { |file| file.puts(rsakey2) }
          timestamp = Time.now - 8*86400 # 8 days older than now
          FileUtils.touch(old_host1_keyfile, :mtime => timestamp)
          FileUtils.touch(old_host2_keyfile, :mtime => timestamp)

          is_expected.to run

          expect(!File.exist?(old_host1_keyfile))
          expect(!File.exist?(old_host2_keyfile))

          # verify resources with ensure absent exist for old key files
          [ 'host1.example.com', 'host2.example.com'].each do |host|
            resource = catalogue.resource('Sshkey', host)
            expect(resource).to_not be_nil
            expect(resource.to_hash[:ensure]).to eq 'absent'
          end
        end
      end

      context 'with expire_days=0 and pre-existing ssh_global_known_hosts dir containing old keys' do
        it 'does not remove old key files and creates sshkey resources with ensure present' do
          # Puppet[:vardir] is dynamically created as a tmpdir by the test
          # framework, when the subject is first created. So create the
          # subject now to retrieve that setting for use in our expectations
          # within this example block.
          subject()
          vardir = Puppet[:vardir]
          ssh_global_known_hosts_dir = File.join(vardir, 'simp',
            'environments', environment, 'simp_autofiles',
            'ssh_global_known_hosts')
          FileUtils.mkdir_p(ssh_global_known_hosts_dir)
          old_host1_keyfile = File.join(ssh_global_known_hosts_dir, 'host1.example.com')
          old_host2_keyfile = File.join(ssh_global_known_hosts_dir, 'host2.example.com')

          File.open(old_host1_keyfile, 'w') { |file| file.puts(rsakey1) }
          File.open(old_host2_keyfile, 'w') { |file| file.puts(rsakey2) }
          timestamp = Time.now - 8*86400 # 8 days older than now
          FileUtils.touch(old_host1_keyfile, :mtime => timestamp)
          FileUtils.touch(old_host2_keyfile, :mtime => timestamp)

          is_expected.to run.with_params(0)

          expect(File.exist?(old_host1_keyfile))
          expect(File.exist?(old_host2_keyfile))

          # verify resources with ensure absent exist for old key files
          [ 'host1.example.com', 'host2.example.com'].each do |host|
            resource = catalogue.resource('Sshkey', host)
            expect(resource).to_not be_nil
            expect(resource.to_hash[:ensure]).to eq 'present'
          end
        end
      end
    end
  end
end
