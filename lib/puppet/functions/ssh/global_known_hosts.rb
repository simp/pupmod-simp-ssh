# @summary Update the ssh_known_hosts files for all hosts, purging old files,
# removing duplicates, and creating catalog resources that are found
#
#  Note: This function if marked as an InternalFunction because it
#  changes the state of the system by adding/removing files and
#  adding catalog resources.
#
Puppet::Functions.create_function(:'ssh::global_known_hosts', Puppet::Functions::InternalFunction) do
  # @param expire_days expire time in days; defaults to 7; value of 0
  #   means never purge
  #
  # @return [None]
  dispatch :global_known_hosts do
    optional_param 'Integer', :expire_days
  end

  def global_known_hosts(expire_days = 7)
    require 'yaml'
    require 'find'
    require 'fileutils'

    env = closure_scope.lookupvar('::environment')
    basedir = "#{Puppet[:vardir]}/simp/environments/#{env}/simp_autofiles/ssh_global_known_hosts"

    # First, write out my key.
    write_this_host_key_file(basedir)

    # Now read all keys, resolve duplicates, and update the catalogue.
    update_catalog(basedir, expire_days)

    # Finally, purge any keys past the expire date. If the date is set to 0,
    # then don't purge.
    return unless expire_days != 0

    Dir.glob("#{basedir}/*").each do |file|
      if (Time.now - File.stat(file).mtime) / 86_400 > expire_days
        FileUtils.rm(file)
      end
    end
  end

  def write_this_host_key_file(basedir)
    # FIXME: accessing facts per the documentation doesn't work in unit tests
    # fqdn = closure_scope['facts']['networking']['fqdn']
    # rsakey = closure_scope['facts']['sshrsakey']
    fqdn = closure_scope.lookupvar('::fqdn')
    rsakey = closure_scope.lookupvar('::sshrsakey')

    begin
      unless FileTest.directory?(basedir)
        FileUtils.mkdir_p(basedir, mode: 0o750)
      end

      unless File.stat(basedir).writable?
        raise("ssh::global_known_hosts: Error, can't write #{basedir}")
      end
    rescue
      raise("ssh::global_known_hosts: Error, #{basedir} must be writable by #{Process.uid}")
    end

    hostkey = File.open("#{basedir}/#{fqdn}", 'w+', 0o640)
    hostkey.puts(rsakey)
    hostkey.close
  end

  def collect_hostnames(basedir)
    hnames = {
      longnames: [],
      shortnames: []
    }

    # Collect current list of hostnames
    Find.find(basedir) do |file|
      next unless !FileTest.directory?(file) && FileTest.readable?(file)

      hname = File.basename(file).strip

      if hname.include?('.')
        hnames[:longnames] << hname
      else
        hnames[:shortnames] << hname
      end
    end

    # Remove any old files that exist that have newer conflicts.
    hnames[:shortnames].dup.each do |short_name|
      long_dup = hnames[:longnames].find { |x| x =~ %r{^#{short_name}\..*$} }
      next unless long_dup
      to_del = nil
      if File.stat("#{basedir}/#{short_name}").mtime < File.stat("#{basedir}/#{long_dup}").mtime
        hnames[:shortnames].delete(short_name)
        to_del = "#{basedir}/#{short_name}"
      else
        hnames[:longnames].delete(long_dup)
        to_del = "#{basedir}/#{long_dup}"
      end

      # FIXME: Shouldn't we remove/modify to ensure-absent any existing catalog entry for
      # the file we will be deleting?
      Puppet.notice("ssh::global_known_hosts is removing '#{to_del}' due to a conflict.")
      FileUtils.rm_f(to_del)
    end
    (hnames[:longnames] + hnames[:shortnames])
  end

  def update_catalog(basedir, expire_days)
    hnames = collect_hostnames(basedir)
    hnames.each do |hname|
      file = "#{basedir}/#{hname}"

      ssh_ensure = 'present'
      if expire_days != 0
        if (Time.now - File.stat(file).mtime) / 86_400 > expire_days
          ssh_ensure = 'absent'
        end
      end

      sshkey_resource_hash = {
        hname => {
          type: 'ssh-rsa',
         host_aliases: hname.split('.').first,
         key: File.open(file, 'r').read.strip,
         ensure: ssh_ensure
        }
      }
      begin
        call_function('create_resources', 'sshkey', sshkey_resource_hash)
      rescue Puppet::Resource::Catalog::DuplicateResourceError
        # FIXME: This will fail if the resource exists.  We should either
        # remove any existing resource before creating it, or modify it in
        # case any of the existing parameters are wrong (notably ensure).
      end
    end
  end
end
