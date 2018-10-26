require 'spec_helper_acceptance'

test_name 'ssh STIG enforcement'

describe 'ssh STIG enforcement' do
  profile_list = ['disa_stig']

  let(:manifest) {
    <<-EOS
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

      ::iptables::listen::tcp_stateful { 'allow_vagrant_ssh':
        trusted_nets => ['ALL'],
        dports     => [22],
      }
      include 'ssh'
    EOS
  }

  let(:hieradata) { <<-EOF
---
ssh::server::conf::app_pki_external_source: '/etc/pki/simp-testing/pki'
# This is for Beaker
ssh::server::conf::permitrootlogin: true
compliance_markup::enforcement:
  - disa_stig
  EOF
  }

  hosts.each do |host|
    #  This is a hack to get the profiles copied up before ssh is locked down.
    #  It is called again in the inspec tests.
    #  Make sure the `profiles_to_validate` is the same so all profiles get copied up.
    before(:all) do
      profiles_to_validate = ['disa_stig']
      profiles_to_validate.each do |profile|
        @inspec = Simp::BeakerHelpers::Inspec.new(host, profile)
      end
    end
    # end of hack
    context 'when enforcing the STIG' do
      let(:hiera_yaml) { <<-EOM
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
      }

      # Using puppet_apply as a helper
      it 'should work with no errors' do
        create_remote_file(host, host.puppet['hiera_config'], hiera_yaml)
        write_hieradata_to(host, hieradata)

        apply_manifest_on(host, manifest, :catch_failures => true)
      end

      it 'should be idempotent' do
        apply_manifest_on(host, manifest, :catch_changes => true)
      end
    end
  end
end
