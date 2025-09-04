# _Description_
#
# Return the list of configured SSHD host keys
#
Facter.add('ssh_host_keys') do
  sshd_command = Facter::Core::Execution.which('sshd')

  confine do
    !sshd_command.nil?
  end

  setcode do
    # sshd -T lists the config dump, which should list all hostkeys
    sshd_out = Facter::Core::Execution.execute(%(\"#{sshd_command}\" -T)).split("\n")

    # Need to strip off the hostkey setting key and space
    hostkeys = sshd_out.grep(%r{^hostkey }).map do |x|
      x.split(' ').last
    end

    hostkeys
  end
end
