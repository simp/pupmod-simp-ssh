require 'spec_helper'

describe 'ssh::client::add_entry' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      let(:facts) do
        facts
      end

      context "on #{os}" do

        let(:title) {'new_run'}

        context 'base' do
          it { should compile.with_all_deps }
          it { should contain_concat_fragment('ssh_config+new_run.conf') }
        end
      end
    end
  end
end
