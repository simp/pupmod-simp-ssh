require 'spec_helper_acceptance'

test_name 'sshd_config drop-in'

# On EL9+ every drop-in in /etc/ssh/sshd_config.d overrides /etc/ssh/sshd_config,
# because the vendor file Includes them at the top and sshd uses the first value
# it reads.  The class therefore writes first-wins keywords to 00-simp.conf,
# which sorts before the vendor (50-redhat.conf), scriptlet
# (25-permitrootlogin.conf) and installer (01-permitrootlogin.conf) drop-ins.
# These checks assert what sshd actually uses (`sshd -T`), not the files.
describe 'sshd_config drop-in' do
  def os_major(host)
    (@os_major ||= {})[host.name] ||= fact_on(host, 'os.release.major').to_i
  end

  let(:manifest) { "include 'ssh'" }
  let(:dropin) { '/etc/ssh/sshd_config.d/00-simp.conf' }
  let(:hieradata) do
    {
      # prohibit-password keeps beaker's key-based root login working while
      # still differing from the planted drop-in below.
      'ssh::server::conf::permitrootlogin' => 'prohibit-password',
      # The vendor 50-redhat.conf sets X11Forwarding yes.
      'ssh::server::conf::x11forwarding'   => false,
      'ssh::server::conf::maxauthtries'    => 4,
      # No accumulating keyword such as Port: those stay in sshd_config, which
      # the last example asserts is unchanged.  05_non_standard_ports_spec
      # covers Port taking effect from sshd_config.
    }
  end

  def sshd_t(host, keyword)
    on(host, %(sshd -T 2>/dev/null | grep -i '^#{keyword} ')).stdout.strip.downcase
  end

  hosts.each do |host|
    context "on #{host.hostname}" do
      it 'plants an installer drop-in and a line an earlier release wrote' do
        next unless os_major(host) >= 9

        # What Anaconda writes when root SSH login is allowed at install.
        create_remote_file(host, '/etc/ssh/sshd_config.d/01-permitrootlogin.conf', "PermitRootLogin yes\n")
        on(host, 'chmod 0600 /etc/ssh/sshd_config.d/01-permitrootlogin.conf')
        # A value an earlier release of this module wrote to sshd_config.
        on(host, %(sed -i '/^MaxAuthTries /d' /etc/ssh/sshd_config && echo 'MaxAuthTries 9' >> /etc/ssh/sshd_config))
        # Earlier suites edit these files (15_config_entries_spec writes to
        # 50-redhat.conf), so compare against their state now, not the vendor's.
        on(host, 'cd /etc/ssh && sha256sum sshd_config sshd_config.d/01-permitrootlogin.conf ' \
                 'sshd_config.d/50-redhat.conf > /root/sshd_config.sha256')
      end

      it 'applies idempotently' do
        set_hieradata_on(host, hieradata)
        apply_manifest_on(host, manifest, catch_failures: true)
        apply_manifest_on(host, manifest, catch_changes: true)
      end

      it 'uses the class values over every drop-in' do
        expect(sshd_t(host, 'permitrootlogin')).to match(%r{^permitrootlogin (prohibit-password|without-password)$})
        expect(sshd_t(host, 'x11forwarding')).to eq('x11forwarding no')
        expect(sshd_t(host, 'maxauthtries')).to eq('maxauthtries 4')
      end

      it 'writes first-wins keywords to a root-only drop-in on EL9+' do
        next unless os_major(host) >= 9

        on(host, %(stat -c '%a %U:%G' #{dropin})) do |result|
          expect(result.stdout.strip).to eq('600 root:root')
        end
        on(host, %(grep -E '^PermitRootLogin prohibit-password$' #{dropin}))
        on(host, %(grep -E '^X11Forwarding no$' #{dropin}))
      end

      it 'leaves sshd_config and the other drop-ins untouched on EL9+' do
        next unless os_major(host) >= 9

        on(host, 'cd /etc/ssh && sha256sum -c /root/sshd_config.sha256')
      end

      # Set, then unset (the value must stay: unset means unmanaged), then
      # removed with remove_entries.  sshd -T reports the keyword as
      # kbdinteractiveauthentication on openssh 8.7+ (EL9+).
      context 'ChallengeResponseAuthentication' do
        let(:cra_hieradata) { hieradata.merge('ssh::server::conf::challengeresponseauthentication' => true) }

        def kbd_t(host)
          on(host, %(sshd -T 2>/dev/null | grep -iE '^(kbdinteractive|challengeresponse)authentication ')).stdout.strip.downcase
        end

        it 'takes effect when set' do
          set_hieradata_on(host, cra_hieradata)
          apply_manifest_on(host, manifest, catch_failures: true)
          apply_manifest_on(host, manifest, catch_changes: true)
          expect(kbd_t(host)).to match(%r{ yes$})
        end

        it 'stays in effect when unset' do
          set_hieradata_on(host, hieradata)
          apply_manifest_on(host, manifest, catch_changes: true)
          expect(kbd_t(host)).to match(%r{ yes$})
        end

        it 'is removed with remove_entries' do
          set_hieradata_on(host, hieradata.merge('ssh::server::conf::remove_entries' => ['ChallengeResponseAuthentication']))
          apply_manifest_on(host, manifest, catch_failures: true)
          apply_manifest_on(host, manifest, catch_changes: true)

          files = ['/etc/ssh/sshd_config']
          files << dropin if os_major(host) >= 9
          on(host, %(grep -iE '^ChallengeResponseAuthentication' #{files.join(' ')}), acceptable_exit_codes: [1])
          # The vendor 50-redhat.conf value applies again.  EL8 has no drop-in,
          # so sshd falls back to its compiled-in default there.
          expect(kbd_t(host)).to match(%r{ no$}) if os_major(host) >= 9
        end
      end

      it 'cleans up the planted drop-in' do
        on(host, 'rm -f /etc/ssh/sshd_config.d/01-permitrootlogin.conf /root/sshd_config.sha256')
      end
    end
  end
end
