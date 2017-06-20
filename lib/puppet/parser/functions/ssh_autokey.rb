module Puppet::Parser::Functions
  newfunction(:ssh_autokey, :type => :rvalue, :doc => <<-EOM) do |args|
    This function generates a random RSA SSH private and public key pair for a passed user.

    Keys are stored in "Puppet[:vardir]/simp/environments/<environment>/simp_autofiles/ssh_autokeys"

    Arguments: username, [option_hash|integer], [return_private]
      * If an integer is the second argument, it will be used as the key strength

      * If a third option is passed AND the second option is not a Hash, the function will return the private key

      * option_hash
        * If option_hash is passed (as a Hash) then the following options are supported:
          - 'key_strength' => Integer
          - 'return_private' => Boolean (Anything but false|nil will be treated as 'true')

      NOTE: A minimum key strength of 1024 will be enforced!
    EOM

    require "timeout"

    function_deprecation([:ssh_autokey, 'This method is deprecated, please use ssh::autokey'])

    username = args[0]
    key_strength = 2048
    return_private = false
    retval = "error"

    if !username
      raise Puppet::ParseError, "Please enter a username!"
    end

    if args[1]
      if args[1].is_a?(Hash)
        key_strength = args[1]['key_strength'].to_i if args[1]['key_strength']
        return_private = args[1]['return_private'] if args[1]['return_private']
      elsif args[1].to_i != 0
        key_strength = args[1].to_i
        return_private = args[2] if args[2]
      else
        raise Puppet::ParseError, "The second argument must be an Integer or a Hash!"
      end
    end

    key_strength = 1024 unless (key_strength > 1024)

    keydir = "#{Puppet[:vardir]}/simp/environments/#{lookupvar('::environment')}/simp_autofiles/ssh_autokeys"

    if ( !File.directory?(keydir) )
      begin
        FileUtils.mkdir_p(keydir,{:mode => 0750})
      rescue
        Puppet.warning "Could not make directory #{keydir}. Ensure that #{keydir} is writable by 'puppet'"
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
        Puppet.warning "ssh-keygen timed out for #{username}"
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
