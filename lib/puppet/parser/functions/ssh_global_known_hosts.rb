module Puppet::Parser::Functions
    newfunction(:ssh_global_known_hosts, :doc => "This function updates the ssh_known_hosts file for all hosts and updates any new ones that are found.\nThis function takes one argument, expire time which is specified in days. Default expire time is 7 days. Set to '0' to never purge.") do |args|

      require 'yaml'
      require 'find'
      require 'fileutils'

      # Do we have an expire time?
      if args[0] then
        expire_days = args[0].to_i
      else
        expire_days = 7
      end

      # First, write out my key.

      fqdn = lookupvar('::fqdn')
      rsakey = lookupvar('::sshrsakey')

      basedir = "#{Puppet[:environmentpath]}/#{lookupvar('::environment')}/simp_autofiles/ssh_global_known_hosts"

      begin
        if not FileTest.directory?(basedir) then
          FileUtils.mkdir_p(basedir,{:mode => 0750})
        end

        if not File.stat(basedir).writable? then
          raise "Can't write #{basedir}"
        end
      rescue
          raise Puppet::ParseError.new("#{basedir} must be writable by #{Process.uid}")
      end

      hostkey = File.open("#{basedir}/#{fqdn}",'w+',0640)
      hostkey.puts(rsakey)
      hostkey.close

      # Now read all keys and add them to the catalogue.

      hnames = {
        :longnames => [],
        :shortnames => []
      }

      # Collect the hostnames
      Find.find(basedir) do |file|
        if ( not FileTest.directory?(file) ) and FileTest.readable?(file)

          hname = File.basename(file).strip

          if hname.include?('.') then
            hnames[:longnames] << hname
          else
            hnames[:shortnames] << hname
          end
        end
      end

      # Remove any old files that exist that have newer conflicts.
      hnames[:shortnames].dup.each do |short_name|
        long_dup = hnames[:longnames].find{|x| x =~ /^#{short_name}\..*$/ }
        if long_dup then
          to_del = nil
          if File.stat("#{basedir}/#{short_name}").mtime < File.stat("#{basedir}/#{long_dup}").mtime then
            hnames[:shortnames].delete(short_name)
            to_del = "#{basedir}/#{short_name}"
          else
            hnames[:longnames].delete(long_dup)
            to_del = "#{basedir}/#{long_dup}"
          end

          Puppet.notice("ssh_global_known_hosts is removing '#{to_del}' due to a conflict.")
          FileUtils.rm_f(to_del)
        end
      end

      (hnames[:longnames] + hnames[:shortnames]).each do |hname|

        file = "#{basedir}/#{hname}"

        ssh_ensure = 'present'
        if expire_days != 0 then
          if (Time.now - File.stat(file).mtime)/86400 > expire_days then
            ssh_ensure = 'absent'
          end
        end

        sshkey_resource = Puppet::DSL::ResourceAPI.new(hname, self, '')
        sshkey_params = {
          :type         => 'ssh-rsa',
          :host_aliases => hname.split('.').first,
          :key          => File.open(file,'r').read.strip,
          :ensure       => ssh_ensure
        }
        sshkey_resource.create_resource("sshkey", hname, sshkey_params)
      end

      # Finally, purge any keys past the expire date. If the date is set to 0,
      # then don't purge.
      if expire_days != 0 then
        Dir.glob("#{basedir}/*").each do |file|
          if (Time.now - File.stat(file).mtime)/86400 > expire_days then
            FileUtils.rm(file)
          end
        end
      end
  end
end
