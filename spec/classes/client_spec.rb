require 'spec_helper'

describe 'ssh::client' do
  on_supported_os.each do |os, os_facts|
    let(:facts) { os_facts }

    context "on #{os}" do
      context 'with default parameters' do
        it { is_expected.to create_class('ssh::client') }
        it { is_expected.to compile.with_all_deps }
        it { is_expected.to create_ssh__client__host_config_entry('*') }
        it { is_expected.to contain_package('openssh-clients').with_ensure('installed') }
        it { is_expected.not_to contain_class('haveged') }
      end

      context 'with add_default_entry = false ' do
        let(:params) { { add_default_entry: false } }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.not_to create_ssh__client__host_config_entry('*') }
      end

      context 'with haveged enabled' do
        let(:params) { { haveged: true } }

        it { is_expected.to contain_class('haveged') }
      end
    end
  end
end
