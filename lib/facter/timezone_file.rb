# _Description_
#
# Return the path for the timezone file the system is using
#
Facter.add("timezone_file") do
  setcode do
    # If /etc/localtime doesn't exist, use the appropriate file in /usr/share/zoneinfo
    timezone_file = File.exist?('/etc/localtime') ? '/etc/localtime' : "/usr/share/zoneinfo/#{Facter.value('timezone')}"
    timezone_file
  end
end