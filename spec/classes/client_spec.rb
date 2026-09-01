require 'spec_helper'

describe 'ssh::client' do
  on_supported_os.each do |os, os_facts|
    let(:facts) { os_facts }

    context "on #{os}" do
      context 'with default parameters' do
        # Reduced blast radius: a bare include installs the package and does
        # nothing else.
        it { is_expected.to create_class('ssh::client') }
        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_package('openssh-clients').with_ensure('installed') }
        it { is_expected.not_to create_ssh__client__host_config_entry('*') }
        it { is_expected.not_to contain_file('/etc/ssh/ssh_config') }
        it { is_expected.not_to contain_file('/etc/ssh/ssh_known_hosts') }
        it { is_expected.not_to contain_class('haveged') }
      end

      context 'with add_default_entry = true' do
        let(:params) { { add_default_entry: true } }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to create_ssh__client__host_config_entry('*') }
        it { is_expected.to contain_file('/etc/ssh/ssh_config').that_requires('Package[openssh-clients]') }
        it { is_expected.to contain_file('/etc/ssh/ssh_known_hosts') }
      end

      context 'with ssh_config_entries' do
        # The vendor client drop-ins wrap their settings in `Match final all`,
        # which the ssh_config type cannot edit -- the documented shape is a
        # drop-in of our own that ssh reads first.
        let(:pre_condition) { "file { '/etc/ssh-entries-test': ensure => file }" }
        let(:params) do
          {
            ssh_config_entries: {
              'simp GSSAPIAuthentication' => {
                'key'    => 'GSSAPIAuthentication',
                'value'  => 'no',
                'target' => '/etc/ssh/ssh_config.d/00-simp.conf',
              },
              'simp ForwardX11Trusted' => {
                'key'     => 'ForwardX11Trusted',
                'value'   => 'no',
                'target'  => '/etc/ssh/ssh_config.d/00-simp.conf',
                'require' => 'File[/etc/ssh-entries-test]',
              },
            },
          }
        end

        it { is_expected.to compile.with_all_deps }
        it {
          is_expected.to contain_ssh_config('simp GSSAPIAuthentication')
            .with_key('GSSAPIAuthentication')
            .with_value('no')
            .with_target('/etc/ssh/ssh_config.d/00-simp.conf')
            .that_requires('Package[openssh-clients]')
        }
        # An entry-supplied `require` is merged with -- never replaces -- the
        # package dependency.
        it {
          is_expected.to contain_ssh_config('simp ForwardX11Trusted')
            .that_requires('Package[openssh-clients]')
            .that_requires('File[/etc/ssh-entries-test]')
        }
        # Everything else stays reduced-blast-radius.
        it { is_expected.not_to create_ssh__client__host_config_entry('*') }
        it { is_expected.not_to contain_file('/etc/ssh/ssh_config') }
      end

      context 'with haveged enabled' do
        let(:params) { { haveged: true } }

        it { is_expected.to contain_class('haveged') }
      end
    end
  end
end
