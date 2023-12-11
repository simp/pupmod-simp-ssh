# _Description_
#
# Return the path for the timezone file the system is using
#
Facter.add("timezone_file") do
  setcode do
    # If /etc/localtime doesn't exist, use the appropriate file in /usr/share/zoneinfo
    timezone_file = ''
    if File.exist?('/etc/localtime')
      timezone_file = '/etc/localtime'
    elsif File.exist?("/usr/share/zoneinfo/#{Facter.value('timezone')}")
      timezone_file = "/usr/share/zoneinfo/#{Facter.value('timezone')}"
    else
      timezone_file = '/usr/share/zoneinfo/UTC'
    end
    timezone_file
  end
end