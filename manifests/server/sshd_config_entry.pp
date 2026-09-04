# @summary Manage a single ``sshd_config`` entry that is safe to declare from
#   outside this module
#
# A thin wrapper around the [`sshd_config`][aug_ssh__sshd_config] type from
# ``augeasproviders_ssh`` that wires the entry into this module's opt-in
# service management:
#
# * ``ssh::server`` is included, so the ``openssh-server`` package is in the
#   catalog and the entry is applied only after it is installed.
# * When ``ssh::server`` manages the ``sshd`` service
#   (``ssh::server::service_ensure``/``ssh::server::service_enable``), the
#   entry notifies ``Service['sshd']`` so the change takes effect.  When the
#   service is unmanaged, nothing is notified and the catalog still compiles.
#
# Other modules should use this instead of a raw ``sshd_config`` resource that
# references ``Package['openssh-server']`` or ``Service['sshd']`` directly,
# since neither resource is guaranteed to be in the catalog.
#
# Give each entry a title distinct from any module-managed keyword (module
# entries use the bare keyword as the title) and set ``key`` explicitly when
# the title is not the keyword itself.
#
# @example Match-block entry from a profile module
#   ssh::server::sshd_config_entry { 'AuthorizedKeysFile GitLab user':
#     key       => 'AuthorizedKeysFile',
#     condition => 'User git',
#     value     => '/var/opt/gitlab/.ssh/authorized_keys',
#   }
#
# @example Remove a setting from the EL9+ vendor drop-in
#   ssh::server::sshd_config_entry { '50-redhat GSSAPIAuthentication':
#     ensure => 'absent',
#     key    => 'GSSAPIAuthentication',
#     target => '/etc/ssh/sshd_config.d/50-redhat.conf',
#   }
#
# @param ensure  Whether the entry should be present or absent
#
# @param key  The ``sshd_config`` keyword.  Defaults to the resource title.
#
# @param value  The value(s) of the keyword.  Required unless ``ensure`` is
#   ``absent``.
#
# @param condition  A ``Match`` block condition (e.g. ``User git``) to place
#   the entry in
#
# @param target  The file to manage the entry in.  Defaults to
#   ``/etc/ssh/sshd_config``.
#
# @param array_append  Whether to add to existing array values or replace them
#
# @param comment  Text to store in a comment immediately above the entry
#
# @author https://github.com/simp/pupmod-simp-ssh/graphs/contributors
#
define ssh::server::sshd_config_entry (
  Enum['present','absent']                    $ensure       = 'present',
  String[1]                                   $key          = $title,
  Optional[Variant[String[1],Array[String[1]]]] $value        = undef,
  Optional[String[1]]                         $condition    = undef,
  Optional[Stdlib::Absolutepath]              $target       = undef,
  Optional[Boolean]                           $array_append = undef,
  Optional[String]                            $comment      = undef,
) {
  include 'ssh::server'

  if ($ensure == 'present') and ($value =~ Undef) {
    fail("Ssh::Server::Sshd_config_entry[${title}]: 'value' is required when 'ensure' is 'present'")
  }

  # Service management is opt-in (see ssh::server); only notify the service
  # when it is actually in the catalog.
  $_notify = $ssh::server::_manage_service ? {
    true    => Service['sshd'],
    default => undef,
  }

  sshd_config { $title:
    ensure       => $ensure,
    key          => $key,
    value        => $value,
    condition    => $condition,
    target       => $target,
    array_append => $array_append,
    comment      => $comment,
    require      => Package['openssh-server'],
    notify       => $_notify,
  }
}
