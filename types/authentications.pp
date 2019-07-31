# Valid SSH Authentication Settings
type Ssh::Authentications = Enum[
  'publickey',
  'hostbased',
  'keyboard-interactive',
  'password',
  'gssapi-with-mic'
]
