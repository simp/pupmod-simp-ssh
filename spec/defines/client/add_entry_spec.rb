require 'spec_helper'

describe 'ssh::client::add_entry' do

  let(:title) {'new_run'}

  context 'base' do
    it { should compile.with_all_deps }
    it { should contain_concat_fragment('ssh_config+new_run.conf') }
  end
end
