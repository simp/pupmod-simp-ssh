require 'spec_helper_acceptance'

test_name 'ssh raw config entries'

# Covers the layer the unit tests cannot see: that raw sshd_config/ssh_config
# entries land where the daemons actually obtain their values (`sshd -T` /
# `ssh -G`), across the vendor drop-in layouts of each EL release.  This is
# the guard against the vendor layout drifting (e.g. the client drop-ins are
# wrapped in `Match final all`, which the ssh_config type cannot edit).
describe 'ssh raw config entries' do
  def os_major(host)
    (@os_major ||= {})[host.name] ||= fact_on(host, 'os.release.major').to_i
  end

  let(:manifest) { "include 'ssh'" }

  hosts.each do |host|
    context "on #{host.hostname}" do
      it 'applies raw entries from hiera idempotently' do
        server_entries =
          if os_major(host) >= 9
            # EL9+: the vendor drop-in is Included at the top of sshd_config
            # and pre-sets these keywords, so it is the file that must change.
            {
              '50-redhat X11Forwarding' => {
                'key'    => 'X11Forwarding',
                'value'  => 'no',
                'target' => '/etc/ssh/sshd_config.d/50-redhat.conf',
              },
              '50-redhat GSSAPIAuthentication' => {
                'ensure' => 'absent',
                'key'    => 'GSSAPIAuthentication',
                'target' => '/etc/ssh/sshd_config.d/50-redhat.conf',
              },
            }
          else
            # EL8 has no sshd_config.d; the main file is the default target.
            {
              'main X11Forwarding' => {
                'key'   => 'X11Forwarding',
                'value' => 'no',
              },
            }
          end

        hieradata = {
          'ssh::server::conf::sshd_config_entries' => server_entries,
          # The vendor *client* drop-ins wrap their settings in
          # `Match final all`, so the documented shape is a drop-in of our
          # own that ssh reads first.
          'ssh::client::ssh_config_entries'        => {
            'simp GSSAPIAuthentication' => {
              'key'    => 'GSSAPIAuthentication',
              'value'  => 'no',
              'target' => '/etc/ssh/ssh_config.d/00-simp.conf',
            },
          },
        }

        set_hieradata_on(host, hieradata)
        apply_manifest_on(host, manifest, catch_failures: true)
        apply_manifest_on(host, manifest, catch_changes: true)
      end

      it 'sets the effective sshd X11Forwarding to no' do
        result = on(host, %(sshd -T 2>/dev/null | grep -i '^x11forwarding'))
        expect(result.stdout.strip.downcase).to eq('x11forwarding no')
      end

      it 'removes the vendor GSSAPIAuthentication so the compiled default applies' do
        next unless os_major(host) >= 9

        # The setting line is gone from the vendor drop-in...
        on(host, %(grep -E '^\\s*GSSAPIAuthentication\\b' /etc/ssh/sshd_config.d/50-redhat.conf), acceptable_exit_codes: [1])
        # ...so sshd falls back to its compiled default (no).
        result = on(host, %(sshd -T 2>/dev/null | grep -i '^gssapiauthentication'))
        expect(result.stdout.strip.downcase).to eq('gssapiauthentication no')
      end

      it 'sets the effective client GSSAPIAuthentication to no' do
        result = on(host, %(ssh -G localhost | grep -i '^gssapiauthentication '))
        expect(result.stdout.strip.downcase).to eq('gssapiauthentication no')
      end
    end
  end
end
