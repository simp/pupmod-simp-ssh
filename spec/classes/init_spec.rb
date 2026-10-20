require 'spec_helper'

describe 'ssh' do
  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:facts) do
          os_facts.merge(
            openssh_version: '8.0',
            timezone_file: '/etc/localtime',
          )
        end

        context 'with default parameters' do
          # Reduced blast radius: a bare `include ssh` installs the packages
          # and manages only the /etc/ssh parent directory.  No service, no
          # sshd_config/ssh_config edits, no scaffolding.
          it { is_expected.to create_class('ssh') }
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_file('/etc/ssh') }
          it { is_expected.to contain_package('openssh-server') }
          it { is_expected.to contain_package('openssh-clients') }

          it { is_expected.not_to contain_service('sshd') }
          it { is_expected.not_to contain_user('sshd') }
          it { is_expected.not_to contain_group('sshd') }
          it { is_expected.not_to contain_file('/var/empty/sshd') }
          it { is_expected.not_to contain_file('/etc/ssh/sshd_config') }
          it { is_expected.not_to contain_file('/etc/ssh/ssh_config') }
          it { is_expected.not_to contain_file('/etc/ssh/ssh_known_hosts') }
          it { is_expected.not_to create_ssh__client__host_config_entry('*') }

          it 'declares no sshd_config resources' do
            expect(catalogue.resources.select { |r| r.type == 'Sshd_config' }).to be_empty
          end

          it 'declares no ssh_config resources' do
            expect(catalogue.resources.select { |r| r.type == 'Ssh_config' }).to be_empty
          end
        end
      end
    end
  end

  context 'noop safety on a node without openssh installed' do
    # The `openssh_version` and `ssh_host_keys` facts are confined to a present
    # `sshd` binary, so they are absent on a fresh node.  The bare-include
    # catalog must still compile (no unguarded fact reads).
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:facts) { os_facts.reject { |k, _| [:openssh_version, :ssh_host_keys].include?(k) } }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.not_to contain_service('sshd') }
      end
    end
  end
end
