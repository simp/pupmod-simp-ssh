# Return the file a module-managed sshd keyword is written to
#
# On EL9+ the vendor `sshd_config` `Include`s `/etc/ssh/sshd_config.d/*.conf`
# at the top of the file, and sshd uses the first value it reads for most
# keywords.  Any drop-in that sets a keyword (the vendor `50-redhat.conf`,
# `25-permitrootlogin.conf` written by the `openssh-server` scriptlet, or
# `01-permitrootlogin.conf` written by Anaconda) therefore overrides what the
# module writes to `sshd_config`.  Those keywords go to a drop-in that sorts
# before all of them instead.
#
# Two groups of keywords stay in `sshd_config`:
#
# * Keywords sshd accumulates across files rather than taking the first
#   value.  No vendor drop-in sets them, so they already take effect in
#   `sshd_config`, and moving them would leave the lines earlier releases
#   wrote there in effect alongside the drop-in: a changed `Port` would keep
#   listening on the old one, and `AllowUsers` would allow both lists.
# * `Ciphers`, `MACs` and `KexAlgorithms`.  On EL9+ the system crypto policy
#   sets them through a vendor drop-in, and it stays in charge of them.
#   Choosing which algorithms override the policy is the job of a crypto
#   sub-policy, not of sshd keywords that would bypass it.
#
# `sshd_config` itself is never edited to make room for the drop-in.  The
# lines earlier releases wrote there stay in place and have no effect once the
# drop-in sets the same keyword.
#
# @param key The sshd configuration keyword
#
# @return [Optional[Stdlib::Absolutepath]]
#   The drop-in path, or `undef` for the default `/etc/ssh/sshd_config`
#
function ssh::sshd_config_target(
  String[1] $key
) >> Optional[Stdlib::Absolutepath] {
  $_in_sshd_config = [
    # Accumulated across files
    'acceptenv',
    'allowgroups',
    'allowusers',
    'denygroups',
    'denyusers',
    'listenaddress',
    'port',
    # Left to the system crypto policy
    'ciphers',
    'kexalgorithms',
    'macs',
  ]

  # Without an OS release fact, keep the pre-drop-in behavior.
  $_major = pick($facts.dig('os', 'release', 'major'), '0')

  if versioncmp(String($_major), '9') >= 0 and !(downcase($key) in $_in_sshd_config) {
    '/etc/ssh/sshd_config.d/00-simp.conf'
  }
  else {
    undef
  }
}
