require 'spec_helper'

describe 'ssh::client' do

  it { should create_class('ssh::client') }
  it { should compile.with_all_deps }
  it { should create_ssh__client__add_entry('*') }
  it { should create_concat_build('ssh_config').with_target('/etc/ssh/ssh_config') }
  it { should create_file('/etc/ssh/ssh_config') }
  it { should contain_package('openssh-clients').with_ensure('latest') }
end
