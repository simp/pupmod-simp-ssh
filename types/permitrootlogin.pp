type Ssh::PermitRootLogin = Variant[
  Boolean,
  Enum['prohibit-password', 'without-password', 'forced-commands-only']
]
