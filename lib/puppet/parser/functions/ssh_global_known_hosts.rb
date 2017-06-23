module Puppet::Parser::Functions
  newfunction(:ssh_global_known_hosts, :doc => "DEPRECATED: This function updates the ssh_known_hosts file for all hosts and updates any new ones that are found.\nThis function takes one argument, expire time which is specified in days. Default expire time is 7 days. Set to '0' to never purge.") do |args|

      raise("ssh_global_known_hosts does not work.  Use ssh::global_known_hosts, instead, and include simp/ssh module in the module's metadata.json") 
  end
end
