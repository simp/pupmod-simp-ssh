require 'spec_helper'

describe 'ssh::client' do
  on_supported_os.each do |os, facts|
    let(:facts) do
      facts
    end

    context "on #{os}" do
      context 'with default parameters' do
        it { is_expected.to create_class('ssh::client') }
        it { is_expected.to compile.with_all_deps }
        it { is_expected.to create_ssh__client__host_config_entry('*') }
        it { is_expected.to contain_package('openssh-clients').with_ensure('latest') }
        it { is_expected.to_not contain_class('haveged') }
      end

      context 'with add_default_entry = false ' do
        let(:params) {{:add_default_entry => false }}
        it { is_expected.to compile.with_all_deps }
        it { is_expected.to_not create_ssh__client__host_config_entry('*') }
      end

      context 'with haveged enabled' do
        let(:params) {{:haveged => true }}
        it { is_expected.to contain_class('haveged') }
      end
    end
  end
end
