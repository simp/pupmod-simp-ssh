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
        let(:params) do
          {
            ssh_config_entries: {
              '50-redhat GSSAPIAuthentication' => {
                'key'    => 'GSSAPIAuthentication',
                'value'  => 'no',
                'target' => '/etc/ssh/ssh_config.d/50-redhat.conf',
              },
            },
          }
        end

        it { is_expected.to compile.with_all_deps }
        it {
          is_expected.to contain_ssh_config('50-redhat GSSAPIAuthentication')
            .with_key('GSSAPIAuthentication')
            .with_value('no')
            .with_target('/etc/ssh/ssh_config.d/50-redhat.conf')
            .that_requires('Package[openssh-clients]')
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
