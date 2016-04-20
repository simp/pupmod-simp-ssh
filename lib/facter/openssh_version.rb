# _Description_
#
# Return the version of sshd
#
Facter.add("openssh_version") do
  sshd_command = Facter::Core::Execution.which('sshd')

  confine do
    not sshd_command.nil?
  end

  setcode do
    version = 'UNKNOWN'

    # There is no explicit version or help flag for sshd.  Pass
    # a garbage '--version' flag, and grab the output.
    sshd_out = Facter::Core::Execution.exec(%(#{sshd_command} --version 2>&1))
    version = sshd_out[/(?<=OpenSSH.)(\d|\.)+/] unless sshd_out.nil?

    version
  end
end
