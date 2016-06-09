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
    # a garbage '-v' flag, and grab the output.
    sshd_out = Facter::Core::Execution.execute(%(#{sshd_command} -v 2>&1))

    # Case insensitive match to openssh followed by any characters (or no characters),
    # proceeded by digits(any number) and decimals.  Return the digits and decimals.
    version = sshd_out.match(/OpenSSH\D*((\d+|\.)+)/i)[1].strip

    version
  end
end
