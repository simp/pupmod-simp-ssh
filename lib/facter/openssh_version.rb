# _Description_
#
# Return the version of sshd
#
if Facter.value(:kernel).downcase == "linux" then
  Facter.add("openssh_version") do
    setcode do
     # There is no explicit version or help flag for sshd.  Pass
     # a garbage '--version' flag, and grab the output.
     sshd_out = %x[/sbin/sshd --version 2>&1]
     version = sshd_out[/(?<=OpenSSH.)(\d|\.)+/]
     version
    end
  end
end
