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
          it { is_expected.to compile.with_all_deps }
          it {
            is_expected.to contain_simpcat_fragment('ssh_config+new_run.conf').with_content(
              %r(Protocol 2$)
            )
            is_expected.to contain_simpcat_fragment('ssh_config+new_run.conf').without_content(
              %r(Cipher )
            )
          }
        end

        context 'with protocol == 1' do
          let(:params){{ :protocol => '1' }}

          it { is_expected.to compile.with_all_deps }
          it {
            is_expected.to contain_simpcat_fragment('ssh_config+new_run.conf').with_content(
              %r(Protocol 1$)
            )
            is_expected.to contain_simpcat_fragment('ssh_config+new_run.conf').with_content(
              %r(Cipher )
            )
          }
        end
        context 'with protocol == 2,1' do
          let(:params){{ :protocol => '2,1' }}

          it { is_expected.to compile.with_all_deps }
          it {
            is_expected.to contain_simpcat_fragment('ssh_config+new_run.conf').with_content(
              %r(Protocol 2,1$)
            )
            is_expected.to contain_simpcat_fragment('ssh_config+new_run.conf').with_content(
              %r(Cipher )
            )
          }
        end

        _protocol_sets = [
          '1',
          '2',
          '1,2',
          '2,1'
        ]
        _protocol_sets.each do |_protocol_set|
          context "with protocol == #{_protocol_set} and use_fips" do
            let(:params){{ :protocol => _protocol_set }}

            _facts = facts.dup
            _facts[:fips_enabled] = true
            let(:facts){ _facts }

            it { is_expected.to compile.with_all_deps }
            it {
              is_expected.to contain_simpcat_fragment('ssh_config+new_run.conf').with_content(
                %r(Protocol 2$)
              )
              is_expected.to contain_simpcat_fragment('ssh_config+new_run.conf').without_content(
                %r(Cipher )
              )
            }
          end
        end
      end
    end
  end
end
