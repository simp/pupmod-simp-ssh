# This function generates a random RSA SSH private and public key pair
# for a passed user.
#
# Keys are stored in 
#   "Puppet[:vardir]/simp/environments/<environment>/simp_autofiles/ssh_autokeys"
#
# Note: This function if marked as an InternalFunction because it 
# changes the state of the system by writing key files.
#
Puppet::Functions.create_function(:'ssh::autokey', Puppet::Functions::InternalFunction) do
  # @param username username for which SSH key pairs will be generated
  # @param options Options hash
  # The following options are supported:
  # - 'key_strength': key length, Integer, defaults to 2048
  # - 'return_private': whether to return the private key, Boolean, defaults to false
  # NOTE: A minimum key strength of 1024 is enforced!
  dispatch :autokey_with_options_hash do
    required_param 'String', :username
    optional_param 'Hash', :options
  end

  # @param username username for which SSH key pairs will be generated
  # @param key_strength key length, defaults to 2048
  # @param return_private whether to return the private key, defaults to false
  # NOTE: A minimum key strength of 1024 is enforced!
  dispatch :autokey do
    required_param 'String', :username
    optional_param 'Integer', :key_strength
    optional_param 'Boolean', :return_private
  end

  def autokey_with_options_hash(username, options=nil)
    key_strength = 2048
    return_private = false

    if options
      key_strength = options['key_strength'].to_i if options['key_strength']
      return_private = options['return_private'] if options['return_private']
    end

    autokey(username, key_strength, return_private)
  end

  def autokey(username, key_strength=nil, return_private=nil)
    require "timeout"

    key_strength = 2048 if key_strength.nil?
    key_strength = 1024 unless (key_strength > 1024)
    return_private = false if return_private.nil?

    retval = "error"

    if !username
      fail('ssh::autokey: Error, username not specified')
    end

    env = closure_scope.lookupvar('::environment')
    keydir = "#{Puppet[:vardir]}/simp/environments/#{env}/simp_autofiles/ssh_autokeys"

    if ( !File.directory?(keydir) )
      begin
        FileUtils.mkdir_p(keydir,{:mode => 0750})
      rescue
        Puppet.warning "ssh::autokey: Could not make directory #{keydir}. Ensure that #{keydir} is writable by 'puppet'"
        return retval
      end
    end

    if ( !File.exists?("#{keydir}/#{username}") )
      begin
        Timeout::timeout(30) do
          system "/usr/bin/ssh-keygen -N '' -q -t rsa -C '' -b #{key_strength} -f #{keydir}/#{username}"
          FileUtils.chmod 0640, "#{keydir}/#{username}"
          FileUtils.chmod 0640, "#{keydir}/#{username}.pub"
        end
      rescue Timeout::Error
        Puppet.warning "ssh::autokey: ssh-keygen timed out for #{username}"
      end
    end

    if ( File.exists?("#{keydir}/#{username}.pub") )
      if return_private
        retval = File.read("#{keydir}/#{username}")
      else
        # Grab the first line from the generated file and spit out only the
        # hash portion.
        retval = File.readlines("#{keydir}/#{username}.pub")[0].split(/\s/)[1]
      end
    end

    return retval
  end
end
