# _Description_
#
# Return the list of configured SSHD host keys
#
Facter.add("ssh_host_keys") do
  sshd_command = Facter::Core::Execution.which('sshd')

  confine do
    not sshd_command.nil?
  end

  setcode do
    hostkeys = []

    # sshd -T lists the config dump, which should list all hostkeys
    sshd_out = Facter::Core::Execution.execute(%(#{sshd_command} -T)).split("\n")

    # Need to strip off the hostkey setting key and space
    hostkeys = sshd_out.grep(/^hostkey /).collect { |x|
      x.split(' ').last
    }

    hostkeys
  end
end
