require 'spec_helper'

# `ssh::server::conf` is a private class configured via APL (Hiera).  It is
# declared here through `include ssh::server` (its public parent) so the
# in-module scope satisfies `assert_private`; parameters are supplied via Hiera
# rather than a resource-style declaration.
describe 'ssh::server::conf' do
  let(:hiera_config) do
    File.expand_path('../../fixtures/hieradata/hiera_compliance_engine.yaml', __dir__)
  end
  let(:pre_condition) { 'include ssh::server' }
  let(:base_facts) { on_supported_os.first.last.merge(openssh_version: '8.0', fips_enabled: false) }

  context 'with no sshd_config parameters (reduced blast radius)' do
    # A bare include leaves /etc/ssh/sshd_config exactly as the package left it.
    let(:facts) { base_facts.merge(custom_hiera: 'none') }

    it { is_expected.to compile.with_all_deps }
    it { is_expected.to create_class('ssh::server::conf') }
    it { is_expected.not_to contain_file('/etc/ssh/sshd_config') }
    it { is_expected.not_to contain_file('/etc/ssh/local_keys') }

    [
      'AcceptEnv', 'Banner', 'Ciphers', 'PermitRootLogin', 'PasswordAuthentication',
      'Port', 'MaxAuthTries', 'UsePAM', 'UsePrivilegeSeparation', 'X11Forwarding'
    ].each do |key|
      it { is_expected.not_to contain_sshd_config(key) }
    end

    it 'declares no sshd_config resources at all' do
      expect(catalogue.resources.select { |r| r.type == 'Sshd_config' }).to be_empty
    end

    it { is_expected.not_to contain_sshd_config_subsystem('sftp') }
  end

  context 'with sshd_config settings provided' do
    let(:facts) { base_facts.merge(custom_hiera: 'conf_settings') }

    it { is_expected.to compile.with_all_deps }
    it { is_expected.to contain_sshd_config('Banner').with_value('/etc/issue.net') }
    it { is_expected.to contain_sshd_config('Banner').that_requires('Package[openssh-server]') }
    it { is_expected.to contain_sshd_config('PermitRootLogin').with_value('no') }
    it { is_expected.to contain_sshd_config('PasswordAuthentication').with_value('yes') }
    it { is_expected.to contain_sshd_config('Port').with_value([22]) }
    it { is_expected.to contain_sshd_config('MaxAuthTries').with_value('6') }
    it { is_expected.to contain_sshd_config('ClientAliveInterval').with_value('600') }
    it { is_expected.to contain_sshd_config('X11Forwarding').with_value('no') }
    it { is_expected.to contain_sshd_config('Ciphers').with_value(['aes256-ctr', 'aes192-ctr']) }
    it { is_expected.to contain_sshd_config('Protocol').with_value('2') }
    it { is_expected.to contain_sshd_config_subsystem('sftp').with_command('/usr/libexec/openssh/sftp-server') }

    # Pointing sshd at the central key location must also create it —
    # AuthorizedKeysFile is absolute (no ~/.ssh fallback), so an entry without
    # the directory breaks every key-based login.  Note service management is
    # NOT requested in this context.
    it { is_expected.to contain_sshd_config('AuthorizedKeysFile').with_value('/etc/ssh/local_keys/%u') }
    it { is_expected.to contain_file('/etc/ssh/local_keys').with_ensure('directory') }

    # Settings that were left unset declare no resource.
    it { is_expected.not_to contain_sshd_config('ListenAddress') }
    it { is_expected.not_to contain_sshd_config('LogLevel') }
    it { is_expected.not_to contain_sshd_config('AllowGroups') }
  end

  # Toggling OATH must never strand `PasswordAuthentication no`: enabling
  # forces it off, and *explicitly* disabling forces it back on (the OATH PAM
  # stack disappears at the same time, so both auth paths would close at once).
  context 'OATH toggle safety' do
    context 'with oath=true' do
      let(:facts) { base_facts.merge(custom_hiera: 'conf_oath') }

      it { is_expected.to compile.with_all_deps }
      it { is_expected.to contain_sshd_config('PasswordAuthentication').with_value('no') }
      it { is_expected.to contain_sshd_config('UsePAM').with_value('yes') }
      it { is_expected.to contain_file('/etc/pam.d/sshd') }
    end

    context 'with oath explicitly false' do
      let(:facts) { base_facts.merge(custom_hiera: 'conf_oath_false') }

      it { is_expected.to compile.with_all_deps }
      it { is_expected.to contain_sshd_config('PasswordAuthentication').with_value('yes') }
      it { is_expected.not_to contain_file('/etc/pam.d/sshd') }
    end

    context 'with oath explicitly false and passwordauthentication explicitly false' do
      let(:facts) { base_facts.merge(custom_hiera: 'conf_oath_false_pwfalse') }

      # The toggle-safety default is `yes`, but an explicit site value wins
      # (stdlib `pick` only skips undef, not false).
      it { is_expected.to compile.with_all_deps }
      it { is_expected.to contain_sshd_config('PasswordAuthentication').with_value('no') }
    end

    context 'with oath unset' do
      let(:facts) { base_facts.merge(custom_hiera: 'none') }

      # Nothing is forced (reduced blast radius).
      it { is_expected.to compile.with_all_deps }
      it { is_expected.not_to contain_sshd_config('PasswordAuthentication') }
    end
  end

  # manage_pam_sshd works on its own; usepam only controls the sshd_config
  # UsePAM entry.
  context 'with manage_pam_sshd alone' do
    let(:facts) { base_facts.merge(custom_hiera: 'conf_pam_sshd') }

    it { is_expected.to compile.with_all_deps }
    it { is_expected.to contain_file('/etc/pam.d/sshd') }
    it { is_expected.not_to contain_sshd_config('UsePAM') }
  end

  # Raw sshd_config resources from Hiera reach the full type — notably
  # `target`, for keys the vendor pre-sets in a drop-in that overrides the
  # main sshd_config (first-match-wins on EL9+).  No notify assertion: like
  # every other entry in this class, restart-on-change comes from the managed
  # service's subscription to the whole class.
  context 'with sshd_config_entries' do
    let(:facts) { base_facts.merge(custom_hiera: 'conf_sshd_config_entries') }

    it { is_expected.to compile.with_all_deps }
    it {
      is_expected.to contain_sshd_config('50-redhat X11Forwarding')
        .with_key('X11Forwarding')
        .with_value('no')
        .with_target('/etc/ssh/sshd_config.d/50-redhat.conf')
        .that_requires('Package[openssh-server]')
    }
    it {
      is_expected.to contain_sshd_config('50-redhat GSSAPIAuthentication')
        .with_ensure('absent')
        .with_key('GSSAPIAuthentication')
        .with_target('/etc/ssh/sshd_config.d/50-redhat.conf')
    }
    # The main-file resource namespace is untouched.
    it { is_expected.not_to contain_sshd_config('X11Forwarding') }

    # An entry-supplied `require` is merged with -- never replaces -- the
    # package dependency.
    it {
      is_expected.to contain_sshd_config('50-redhat PrintMotd')
        .that_requires('Package[openssh-server]')
        .that_requires('File[/etc/ssh]')
    }
  end

  # An entry pointed at the class's own drop-in (as the 9.1.0-9.3.0 README
  # suggested) keeps precedence: the class leaves that keyword to it rather
  # than both rewriting the same line on every run.
  context 'with sshd_config_entries in 00-simp.conf' do
    let(:dropin) { '/etc/ssh/sshd_config.d/00-simp.conf' }

    context 'on EL9' do
      let(:facts) do
        os = base_facts[:os].merge(release: { 'major' => '9', 'full' => '9.0' })
        base_facts.merge(os: os, custom_hiera: 'conf_dropin_entries')
      end

      it { is_expected.to compile.with_all_deps }
      it { is_expected.to contain_sshd_config('site X11Forwarding').with_value('yes').with_target(dropin) }
      # Matched case-insensitively, and an ensure => absent entry counts too.
      it { is_expected.to contain_sshd_config('site maxauthtries').with_ensure('absent') }
      it { is_expected.not_to contain_sshd_config('MaxAuthTries') }
      # The class's own value is not written; remove_entries still removes the
      # keyword from sshd_config but leaves the entry's line in the drop-in.
      it { is_expected.to contain_sshd_config('X11Forwarding').with_ensure('absent').without_target }
      it { is_expected.not_to contain_sshd_config("X11Forwarding in #{dropin}") }
      # Other keywords are unaffected, as are entries with a condition.
      it { is_expected.to contain_sshd_config('PermitRootLogin').with_value('no').with_target(dropin) }
      it { is_expected.to contain_sshd_config('Banner').with_target(dropin) }
    end

    context 'on EL8' do
      let(:facts) do
        os = base_facts[:os].merge(release: { 'major' => '8', 'full' => '8.10' })
        base_facts.merge(os: os, custom_hiera: 'conf_dropin_entries')
      end

      # The class writes to sshd_config on EL8, so there is nothing to yield.
      it { is_expected.to compile.with_all_deps }
      it { is_expected.to contain_sshd_config('MaxAuthTries').with_value('4').without_target }
    end
  end

  context 'with remove_entries' do
    let(:facts) { base_facts.merge(custom_hiera: 'conf_remove') }

    it { is_expected.to compile.with_all_deps }
    # A key in the remove list is not added even when its parameter is set...
    it { is_expected.to contain_sshd_config('PermitRootLogin').with_ensure('absent') }
    # ...and an explicit removal is declared.
    it { is_expected.to contain_sshd_config('GSSAPIAuthentication').with_ensure('absent') }
    # On EL9+ a key the class writes to the drop-in is removed from there too.
    it {
      is_expected.to contain_sshd_config('GSSAPIAuthentication in /etc/ssh/sshd_config.d/00-simp.conf')
        .with_ensure('absent')
        .with_key('GSSAPIAuthentication')
        .with_target('/etc/ssh/sshd_config.d/00-simp.conf')
    }
  end

  # On EL9+ drop-ins override sshd_config (first value wins), so the class
  # writes first-wins keywords to a drop-in that sorts before them.
  context 'sshd_config drop-in' do
    let(:dropin) { '/etc/ssh/sshd_config.d/00-simp.conf' }

    def facts_for(major)
      os = base_facts[:os].merge(release: { 'major' => major, 'full' => "#{major}.0" })
      base_facts.merge(os: os)
    end

    ['9', '10'].each do |major|
      context "with sshd_config settings on EL#{major}" do
        let(:facts) { facts_for(major).merge(custom_hiera: 'conf_settings') }

        it { is_expected.to compile.with_all_deps }
        it {
          is_expected.to contain_file(dropin)
            .with_ensure('file')
            .with_owner('root')
            .with_group('root')
            .with_mode('0600')
            .with_selinux_ignore_defaults(true)
        }

        ['Banner', 'PermitRootLogin', 'PasswordAuthentication', 'MaxAuthTries', 'X11Forwarding'].each do |key|
          it { is_expected.to contain_sshd_config(key).with_target(dropin).that_requires("File[#{dropin}]") }
        end

        # Accumulated across files, or left to the crypto policy.
        ['Port', 'Ciphers'].each do |key|
          it { is_expected.to contain_sshd_config(key).without_target }
        end

        # Subsystem is still written to sshd_config.
        it { is_expected.to contain_sshd_config_subsystem('sftp').without_target }
      end

      context "with no sshd_config parameters on EL#{major}" do
        let(:facts) { facts_for(major).merge(custom_hiera: 'none') }

        it { is_expected.not_to contain_file(dropin) }
      end
    end

    context 'with sshd_config settings on EL8' do
      let(:facts) { facts_for('8').merge(custom_hiera: 'conf_settings') }

      it { is_expected.to compile.with_all_deps }
      it { is_expected.not_to contain_file(dropin) }
      it { is_expected.to contain_sshd_config('PermitRootLogin').without_target }
    end
  end

  # On EL9+ the vendor 50-redhat.conf drop-in overrides the main sshd_config
  # (first-match-wins), so OATH requires a drop-in that sorts first.  No
  # notify assertion: the drop-in does not notify the sshd service directly
  # (the service, when managed, subscribes to the whole class).
  context 'kbdinteractive drop-in' do
    let(:el9_facts) do
      os = base_facts[:os].merge(release: { 'major' => '9', 'full' => '9.0' })
      base_facts.merge(os: os)
    end

    context 'with oath=true on EL9' do
      let(:facts) { el9_facts.merge(custom_hiera: 'conf_oath') }

      it { is_expected.to compile.with_all_deps }
      it {
        is_expected.to contain_file('/etc/ssh/sshd_config.d/00-simp-kbdinteractive.conf')
          .with_ensure('file')
          .with_content(%r{^KbdInteractiveAuthentication yes$})
      }
      # The drop-in above carries OATH's value, so nothing is written to
      # 00-simp.conf that would outlive OATH.
      it { is_expected.not_to contain_sshd_config('ChallengeResponseAuthentication') }
    end

    # A site value is written to 00-simp.conf as usual.
    context 'with challengeresponseauthentication set on EL9' do
      let(:facts) { el9_facts.merge(custom_hiera: 'conf_cra') }

      it { is_expected.to compile.with_all_deps }
      it {
        is_expected.to contain_sshd_config('ChallengeResponseAuthentication')
          .with_value('no')
          .with_target('/etc/ssh/sshd_config.d/00-simp.conf')
      }
    end

    context 'with oath=false on EL9' do
      let(:facts) { el9_facts.merge(custom_hiera: 'none') }

      it { is_expected.to compile.with_all_deps }
      it {
        is_expected.to contain_file('/etc/ssh/sshd_config.d/00-simp-kbdinteractive.conf')
          .with_ensure('absent')
      }
    end

    context 'with oath=true on EL8' do
      let(:facts) do
        os = base_facts[:os].merge(release: { 'major' => '8', 'full' => '8.10' })
        base_facts.merge(os: os, custom_hiera: 'conf_oath')
      end

      it { is_expected.to compile.with_all_deps }
      it { is_expected.not_to contain_file('/etc/ssh/sshd_config.d/00-simp-kbdinteractive.conf') }
      # EL8 has no drop-in, so OATH still forces the sshd_config value.
      it { is_expected.to contain_sshd_config('ChallengeResponseAuthentication').with_value('yes').without_target }
    end
  end
end
