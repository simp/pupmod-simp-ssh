require 'spec_helper_acceptance'

test_name 'ssh STIG enforcement'

describe 'ssh STIG enforcement' do
  let(:manifest) do
    <<~EOS
      file { '/etc/ssh/local_keys/vagrant':
        ensure  => file,
        owner   => 'vagrant',
        group   => 'vagrant',
        source  => '/home/vagrant/.ssh/authorized_keys',
        mode    => '0644',
        seltype => 'sshd_key_t',
       }

      file { '/etc/ssh/local_keys/root':
        ensure  => file,
        owner   => 'root',
        group   => 'root',
        source  => '/home/vagrant/.ssh/authorized_keys',
        mode    => '0644',
        seltype => 'sshd_key_t',
       }

      iptables::listen::tcp_stateful { 'allow_vagrant_ssh':
        trusted_nets => ['ALL'],
        dports     => [22],
      }
      include 'ssh'
    EOS
  end

  let(:hieradata) do
    <<~EOF
      ---
      simp_options::pki: true
      simp_options::pki::source: '/etc/pki/simp-testing/pki'
      # This is for Beaker
      ssh::server::conf::permitrootlogin: true
      compliance_markup::enforcement:
        - disa_stig
    EOF
  end

  hosts.each do |host|
    context 'when enforcing the STIG' do
      let(:hiera_yaml) do
        <<~EOM
          ---
          version: 5
          hierarchy:
            - name: Common
              path: common.yaml
            - name: Compliance
              lookup_key: compliance_markup::enforcement
          defaults:
            data_hash: yaml_data
            datadir: "#{hiera_datadir(host)}"
        EOM
      end

      # Using puppet_apply as a helper
      it 'works with no errors' do
        create_remote_file(host, host.puppet['hiera_config'], hiera_yaml)
        write_hieradata_to(host, hieradata)

        apply_manifest_on(host, manifest, catch_failures: true)
      end

      it 'is idempotent' do
        apply_manifest_on(host, manifest, catch_changes: true)
      end
    end
  end
end
