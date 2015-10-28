Puppet::Type.newtype(:sshkey_prune) do
  @desc = "Prune unknown SSH Keys from the file in $name"

  newparam(:name, :namevar => true) do
    desc "The file that you wish to prune"
  end

  newproperty(:prune) do
    newvalues(:true,:false)
    defaultto(:true)
    desc "Whether or not to prune the file in $name"

    def insync?(is)
      # Expects a list of SSH keys already in the target file.
      provider.insync?(is)
    end

    def sync
      # Deletes all unknown keys from the target file.
      provider.sync
    end

    def retrieve
      # Gets the list of SSH keys already in the target file.
      provider.retrieve
    end

    def change_to_s(currentvalue, newvalue)
      provider.change_to_s
    end
  end

  autorequire(:sshkey) do
    req = []
    resource = catalog.resources.find_all { |r|
      r.is_a?(Puppet::Type.type(:sshkey))
    }
    if not resource.empty? then
      req << resource
    end
    req.flatten!
    req.each { |r| debug "Autorequiring #{r}" }
    req
  end
end
