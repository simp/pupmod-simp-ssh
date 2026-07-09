# AGENTS.md

This file provides guidance to AI agents when working with code in this repository.

## What this module does

`simp-ssh` is a large, central SIMP Puppet module that manages both the **SSH
client** (`/etc/ssh/ssh_config`) and the **SSH server** (`sshd` + `/etc/ssh/sshd_config`)
on Enterprise Linux systems. It installs the openssh packages, manages the
`sshd` service, user/group, host keys and `/var/empty/sshd` chroot scaffolding,
and drives `sshd_config` / `ssh_config` entry-by-entry through the
`augeasproviders_ssh` types (`sshd_config`, `sshd_config_subsystem`,
`ssh_config`). A defining feature is **FIPS-aware cipher / MAC / key-exchange
selection**: when unset, cipher/MAC/kex lists are chosen automatically based on
whether the host is in FIPS mode.

The top-level `ssh` class is a thin switchboard: it manages `/etc/ssh` and
conditionally includes the client and/or server stacks
(`manifests/init.pp`). Almost every class is **public API** — the only
private class is the server engine `ssh::server::conf`.

### Business logic

**Client / server split.** The module is organized into a client stack and a
server stack, each with its own `params` class holding the FIPS vs non-FIPS
crypto lists.

- **`ssh` (`manifests/init.pp`)** — Entry class. `Boolean $enable_client`
  and `Boolean $enable_server` (both default `true`) toggle which stack is
  included (`init.pp`). Also manages the `/etc/ssh` directory.

- **`ssh::client` (`manifests/client.pp`)** — Manages `/etc/ssh/ssh_config`,
  `/etc/ssh/ssh_known_hosts`, and the `openssh-clients` package. When
  `$add_default_entry` (default `true`) it declares
  `ssh::client::host_config_entry { '*': }` for a sane default `Host *` block
  (`client.pp`). `$haveged` (default from `simp_options::haveged`) pulls
  in the optional `haveged` module after an `assert_optional_dependency`
  (`client.pp`). `$fips` (default from `simp_options::fips`) is the
  FIPS toggle consulted by the host-entry define.

- **`ssh::client::params` (`manifests/client/params.pp`)** — Data-only class
  holding the client crypto lists: `$fips_macs`/`$fips_ciphers` (the
  FIPS-constrained sets, `params.pp`) and the expanded `$macs`/`$ciphers`
  used outside FIPS (`params.pp`). Also sets `$gssapiauthentication` from
  the `ipa` fact (`params.pp`).

- **`ssh::client::host_config_entry` (`manifests/client/host_config_entry.pp`)** —
  Public **define** that emits one `Host` block into `ssh_config` as a large set
  of per-key `ssh_config` resources (one per SSH client option). The `name` is
  the `Host` pattern. It performs its **own** FIPS-aware selection mirroring the
  server: MACs, ciphers, and protocol are chosen from `ssh::client::params`
  based on `$ssh::client::fips or $facts['fips_enabled']`
  (`host_config_entry.pp`). Host titles are run through
  `ssh::format_host_entry_for_sorting` so wildcard entries sort last
  (`host_config_entry.pp`).

- **`ssh::authorized_keys` (`manifests/authorized_keys.pp`)** — Declares
  `ssh_authorized_key` resources from the `$keys` Hash in Hiera. Accepts three
  value shapes per user — a raw pubkey String, an Array of pubkey Strings, or a
  full options Hash — normalizing String/Array forms via
  `ssh::parse_ssh_pubkey` (`authorized_keys.pp`). **Warning in the
  docstring:** this creates a resource per key per user, so large key sets
  belong in a central source (LDAP), not Hiera.

- **`ssh::server` (`manifests/server.pp`)** — Manages the
  `openssh-server` package, the `sshd` service, the `sshd` user/group (uid/gid
  `74`), `/etc/ssh/moduli`, and the `/var/empty/sshd` privilege-separation
  chroot. It `include`s `ssh` and the private `ssh::server::conf`, and the
  `sshd` service `subscribe`s to `Class['ssh::server::conf']`
  (`server.pp`). It manages permissions on every host key reported by
  the `ssh_host_keys` fact; when `pki` is enabled it additionally sources the
  RSA host key from the PKI key and regenerates the pubkey via `exec['gensshpub']`
  (`server.pp`). The `openssh-ldap` package is managed only when
  `ssh::server::conf::_use_ldap` is true (`server.pp`).

- **`ssh::server::params` (`manifests/server/params.pp`)** — Data-only class
  holding the server crypto lists and version-dependent knobs: `$fallback_ciphers`
  (`params.pp`), FIPS sets `$fips_kex_algorithms`/`$fips_macs`/`$fips_ciphers`
  (`params.pp`), and the expanded non-FIPS `$kex_algorithms`/`$macs`
  (`params.pp`). Version guards: `curve25519-sha256@libssh.org` is only
  added on openssh >= 6.5 (`params.pp`); `$rhostsrsaauthentication` is
  `undef` on openssh >= 7.4 (option removed) and `false` below (`params.pp`).

- **`ssh::server::conf` (`manifests/server/conf.pp`)** — **The private engine.**
  `assert_private()` at `server/conf.pp` — this is the *only* private class;
  consumers reach it via `include 'ssh::server'`, never directly. It carries the
  full parameter surface for `sshd_config` and translates each parameter into an
  `sshd_config` resource via the `ssh::add_sshd_config` helper
  (`server/conf.pp`), which respects the `$remove_entries` opt-out list.
  Boolean-to-`yes`/`no` translation goes through `ssh::config_bool_translate`.
  Its logic:
  - **FIPS-aware crypto selection** (`server/conf.pp`): when `macs` /
    `ciphers` / `kex_algorithms` are unset, it picks the `fips_*` list from
    `ssh::server::params` if `$fips or $facts['fips_enabled']`, else the
    expanded list. `$enable_fallback_ciphers` (default `true`) appends
    `$fallback_ciphers` for interoperability with non-SIMP hosts
    (`server/conf.pp`).
  - **AuthorizedKeysCommand routing** (`server/conf.pp`): an explicit
    `authorizedkeyscommand` wins; else `sssd` → `sss_ssh_authorizedkeys`; else
    LDAP → `ssh-ldap-wrapper`.
  - **OATH two-factor** (`server/conf.pp`): when `oath`, forces
    `usepam` true, includes the optional `oath` module, sets
    `challengeresponseauthentication` true / `passwordauthentication` false, and
    renders `/etc/pam.d/sshd` from `templates/etc/pam.d/sshd.epp`.
  - **Version-dependent entries** (`server/conf.pp`):
    `UsePrivilegeSeparation` is written on openssh < 7.5 and removed on >= 7.5.
  - **Optional integrations**, each guarded by `assert_optional_dependency`:
    PKI (`server/conf.pp`), SELinux port labeling for non-22 ports
    (`server/conf.pp`), firewall via `iptables`
    (`server/conf.pp`), and `tcpwrappers` (`server/conf.pp`).

### Gotchas / non-obvious details

- **Almost everything is public API.** `assert_private()` appears in exactly one
  manifest, `ssh::server::conf` (`server/conf.pp`). Every other class and
  the `host_config_entry` define are consumer-facing; changing their parameters
  is a breaking change.
- **FIPS logic is duplicated across client and server.** Both the server engine
  (`server/conf.pp`) and the client host-entry define
  (`host_config_entry.pp`) independently select crypto lists based on
  `$fips or $facts['fips_enabled']`, reading from their respective `params`
  classes. Change one crypto policy and you likely need to change both.
- **`fips_enabled` fact overrides the toggle.** Even with `fips => false`, a
  live `fips_enabled` fact forces FIPS crypto lists — the check is
  `$fips or $facts['fips_enabled']`, not `$fips` alone.
- **`sshd_config` is managed entry-by-entry, not as a whole file.** Config lines
  are individual `sshd_config` resources from `augeasproviders_ssh`; the
  docstring notes you *can* set `sshd` variables via Augeas outside this class.
  `Match` blocks are explicitly unsupported by `custom_entries` /
  `remove_entries` and must use `sshd_config_match` directly
  (`server/conf.pp`).
- **`PasswordAuthentication` is always managed** so that switching to/from OATH
  cannot lock you out (`server/conf.pp`); OATH forces it off
  (`server/conf.pp`).
- **LDAP is suppressed by SSSD.** `$_use_ldap` is false whenever `sssd` is also
  true (`server/conf.pp`), and that variable gates the `openssh-ldap`
  package in `ssh::server`.
- **`simp/simp_options` is NOT a declared dependency**, yet the manifests
  consume the `simp_options::*` seam via `simplib::lookup` (provided by
  `simp/simplib`). See the seam table below.
- **`simp/pam` is declared optional but never asserted.** It is listed in
  `metadata.json` `simp.optional_dependencies`, but there is **no**
  `assert_optional_dependency` call for it — the PAM integration is driven by
  the `simp_options::pam` seam (`server/conf.pp`) and PAM management is done
  in-module by rendering `/etc/pam.d/sshd` from the EPP template, not by
  including a `pam` class. Treat it as a soft/consumed dependency, not a
  runtime-asserted one.
- **Two entropy/interop defaults are surprising:** `enable_fallback_ciphers`
  defaults `true` (weakens the auto-selected set for non-SIMP interop), and the
  server manages a `haveged` include only when `simp_options::haveged` is set.

## The `simp_options` / `simplib::lookup` seam

This is the module's real feature-toggle seam. Every SIMP integration flows
through `simplib::lookup('simp_options::*', { 'default_value' => ... })` with an
explicit default, so the module works whether or not `simp_options` is included.

| Key | Where | `default_value` |
|-----|-------|-----------------|
| `simp_options::haveged` | `client.pp`, `server/conf.pp` | `false` |
| `simp_options::fips` | `client.pp`, `server/conf.pp` | `false` |
| `simp_options::package_ensure` | `client.pp`, `server.pp`, `server.pp` | `'installed'` |
| `simp_options::pam` | `server/conf.pp` | `true` |
| `simp_options::tcpwrappers` | `server/conf.pp` | `false` |
| `simp_options::pki::source` | `server/conf.pp` | `'/etc/pki/simp/x509'` |
| `simp_options::firewall` | `server/conf.pp` | `false` |
| `simp_options::ldap` | `server/conf.pp` | `false` |
| `simp_options::oath` | `server/conf.pp` | `false` |
| `simp_options::pki` | `server/conf.pp` | `false` |
| `simp_options::sssd` | `server/conf.pp` | `false` |

Keep routing SIMP feature toggles through this pattern with an explicit
`default_value` rather than assuming `simp_options` is present.

## Dependencies

Hard dependencies (from `metadata.json` `dependencies`):

- `puppet/augeasproviders_ssh` `>= 2.5.0 < 8.0.0` — provides the `sshd_config`,
  `sshd_config_subsystem`, and `ssh_config` types/providers this module drives.
- `puppetlabs/stdlib` `>= 8.0.0 < 10.0.0`.
- `simp/simplib` `>= 4.9.0 < 5.0.0` — provides `simplib::lookup`,
  `simplib::assert_optional_dependency`, `simplib::assert_metadata`, the
  `Simplib::*` type aliases, and `nets2ddq`.

Optional dependencies (from `metadata.json` `simp.optional_dependencies`). All
but `simp/pam` are guarded at runtime by `simplib::assert_optional_dependency`
at the cited line:

- `simp/haveged` `>= 0.4.5 < 1.0.0` — `client.pp`, `server/conf.pp`
- `simp/pki` `>= 6.2.0 < 7.0.0` — `server/conf.pp`
- `simp/oath` `>= 0.1.0 < 1.0.0` — `server/conf.pp`
- `simp/selinux` `>= 2.6.1 < 4.0.0` — `server/conf.pp`
- `simp/vox_selinux` `>= 3.1.0 < 4.0.0` — `server/conf.pp`
- `puppet/selinux` `>= 1.6.1 < 6.0.0` — `server/conf.pp`
- `simp/iptables` `>= 6.5.3 < 8.0.0` — `server/conf.pp`
- `simp/tcpwrappers` `>= 6.2.0 < 7.0.0` — `server/conf.pp`
- `simp/pam` `>= 6.8.3 < 8.0.0` — declared optional but has **no**
  `assert_optional_dependency` call; consumed via the `simp_options::pam` seam
  and the in-module PAM template (see Gotchas).

Runtime requirement (from `metadata.json` `requirements`):
`puppet >= 7.0.0 < 9.0.0`. This is an **old baseline** and still names
**puppet**. SIMP is migrating Puppet → OpenVox; when `metadata.json` switches
this requirement to `openvox`, update this line to match.

Supported OS matrix (from `metadata.json`): CentOS 7/8/9; RedHat 7/8/9;
OracleLinux 7/8/9; Rocky 8/9; AlmaLinux 8/9.

## Repository layout

- `manifests/init.pp` — the `ssh` switchboard class.
- `manifests/client.pp`, `manifests/client/params.pp`,
  `manifests/client/host_config_entry.pp` — the client stack (class, data,
  per-`Host` define).
- `manifests/authorized_keys.pp` — Hiera-driven `ssh_authorized_key` loop.
- `manifests/server.pp`, `manifests/server/params.pp` — server package/service/
  keys and server crypto data.
- `manifests/server/conf.pp` — the private `sshd_config` engine
  (`assert_private()`).
- `functions/` — **Puppet-language** functions: `ssh::add_sshd_config`
  (`add_sshd_config.pp`) and `ssh::parse_ssh_pubkey` (`parse_ssh_pubkey.pp`).
- `lib/puppet/functions/ssh/` — **Ruby** functions: `autokey`,
  `config_bool_translate`, `format_host_entry_for_sorting`, `global_known_hosts`
  (six `ssh::` functions total across `functions/` and `lib/`).
- `lib/facter/` — custom facts `openssh_version` (parses `sshd -v`),
  `ssh_host_keys` (parses `sshd -T`), `timezone_file`.
- `lib/puppet/type/sshkey_prune.rb` + `lib/puppet/provider/sshkey_prune/prune.rb`
  — the `sshkey_prune` type/provider that removes unmanaged keys from a known-
  hosts file.
- `lib/augeas/lenses/ssh.aug` — bundled Augeas lens.
- `types/` — four type aliases: `Ssh::Authentications`, `Ssh::Loglevel`,
  `Ssh::PermitRootLogin`, `Ssh::Syslogfacility`.
- `templates/etc/pam.d/sshd.epp` — the sshd PAM stack (injects OATH when
  enabled).
- `metadata.json` — deps, optional deps, OS matrix, Puppet requirement.
- `REFERENCE.md` — generated Puppet Strings reference.
- `spec/` — rspec-puppet unit tests plus a beaker acceptance suite (run
  manually; not wired into CI — see below).

**CI (`.github/workflows/pr_tests.yml`):** the standard six SIMP jobs —
`puppet-syntax`, `puppet-style`, `ruby-style`, `file-checks`, `releng-checks`,
`spec-tests`. **There is no acceptance job**; the beaker suites and the two
nodesets (`spec/acceptance/nodesets/default.yml`, `oel.yml`) are run manually.

## Common commands

```sh
# Install dependencies
bundle install

# Run all unit tests
bundle exec rake spec

# Run one spec file
bundle exec rspec spec/classes/server/conf_spec.rb

# Puppet lint
bundle exec rake lint

# Ruby lint
bundle exec rake rubocop

# Regenerate REFERENCE.md from puppet-strings docstrings
puppet strings generate --format markdown --out REFERENCE.md

# Run a beaker acceptance suite (manual — not in CI)
bundle exec rake beaker:suites[default]
bundle exec rake beaker:suites[oel]
```

Relevant gem pins (from `Gemfile`): the tested Puppet range defaults to
`['>= 7', '< 9']` (`Gemfile`) and only the **puppet** gem is installed
(`gem 'puppet', puppet_version`, `Gemfile`) — no `openvox` gem yet.
`rubocop ~> 1.88.0` (`Gemfile`), `puppetlabs_spec_helper ~> 8.0.0`
(`Gemfile`), `simp-rake-helpers ~> 5.24.0` (`Gemfile`),
`simp-beaker-helpers ~> 2.0.0` (`Gemfile`). `spec/spec_helper.rb` requires
`puppetlabs_spec_helper/module_spec_helper`.

## Conventions

- Preserve the `@summary` / `@param` puppet-strings docstrings — they drive
  `REFERENCE.md`. Regenerate `REFERENCE.md` after changing docs or parameters.
- Add or remove `sshd_config` entries through the `ssh::add_sshd_config` helper
  (which honors `$remove_entries`), and translate booleans with
  `ssh::config_bool_translate` — don't hand-roll `sshd_config` resources in the
  engine.
- Keep crypto defaults (ciphers/MACs/kex) in the `*::params` classes, split into
  `fips_*` and expanded lists, and keep the client define and the server engine
  in sync when changing crypto policy.
- Guard every optional integration with `simplib::assert_optional_dependency`
  before `include`-ing it, as the existing PKI / SELinux / firewall /
  tcpwrappers / haveged / oath branches do — never hard-`include` an optional
  module.
- Continue routing SIMP feature toggles through
  `simplib::lookup('simp_options::*', { 'default_value' => ... })` rather than
  assuming `simp_options` is included.
- `Gemfile`, `spec/spec_helper.rb`, and the CI workflows carry a **puppetsync**
  notice — they are baseline-managed and the next sync overwrites local edits.
  Push changes to those files upstream to the baseline, not here.
- Match the existing 2-space Puppet indentation and the aligned-arrow /
  aligned-`=` parameter style used across the manifests.
</content>
</invoke>
