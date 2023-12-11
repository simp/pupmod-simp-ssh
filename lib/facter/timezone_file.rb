# _Description_
#
# Return the path for the timezone file the system is using
#
Facter.add(:timezone_file) do
  confine kernel: :linux
  setcode do
    # If /etc/localtime doesn't exist, use the appropriate file in /usr/share/zoneinfo
    timezone_file = if File.exist?('/etc/localtime')
                      '/etc/localtime'
                    elsif File.exist?("/usr/share/zoneinfo/#{Facter.value('timezone')}")
                      "/usr/share/zoneinfo/#{Facter.value('timezone')}"
                    else
                      '/usr/share/zoneinfo/UTC'
                    end
    timezone_file
  end
end
