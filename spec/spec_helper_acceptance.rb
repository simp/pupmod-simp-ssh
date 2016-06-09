require 'beaker-rspec'
require 'tmpdir'
require 'yaml'
require 'simp/beaker_helpers'
include Simp::BeakerHelpers

unless ENV['BEAKER_provision'] == 'no'
  hosts.each do |host|
    # Install Puppet
    if host.is_pe?
      install_pe
    else
      install_puppet
    end
  end
end

ssh_test_script = %q(#!/usr/bin/env ruby
require 'pty'
require 'expect'
user = ARGV[0]
host = ARGV[1]
pass = ARGV[2]
PTY.spawn('ssh','-o StrictHostKeyChecking=no',host,'-l',user) do |read,write,pid|
  begin
    while !read.eof? do
      # if the line is a password prompt:
      read.expect(/password:*/i, timeout=5) do |text|
        write.puts(pass)
        sleep(1)
        write.puts('exit')
        puts "Logged in successfully."
      end
      # if the line says denied
      read.expect(/.*denied.*/i, timeout=5) do |text|
        write.puts('^C')
        exit 1
        puts "Failed to log in."
      end
    end
  rescue Errno::EIO
  end
end
)

RSpec.configure do |c|
  # ensure that environment OS is ready on each host
  fix_errata_on hosts

  # Readable test descriptions
  c.formatter = :documentation

  # Configure all nodes in nodeset
  c.before :suite do
    begin
      # Install modules and dependencies from spec/fixtures/modules
      copy_fixture_modules_to( hosts )

      # Generate and install PKI certificates on each SUT
      Dir.mktmpdir do |cert_dir|
        run_fake_pki_ca_on( default, hosts, cert_dir )
        hosts.each{ |sut| copy_pki_to( sut, cert_dir, '/etc/pki/simp-testing' )}
      end

      # add PKI keys to server
      server = only_host_with_role(hosts, 'server')
      copy_keydist_to(server)

      # send ssh test script to the server
      client = only_host_with_role(hosts, 'client')
      install_package(server, 'expect')
      install_package(client, 'expect')
      create_remote_file(hosts, '/tmp/ssh_test_script', ssh_test_script)
      on(hosts, "chmod +x /tmp/ssh_test_script")
    rescue StandardError, ScriptError => e
      if ENV['PRY']
        require 'pry'; binding.pry
      else
        raise e
      end
    end
  end
end