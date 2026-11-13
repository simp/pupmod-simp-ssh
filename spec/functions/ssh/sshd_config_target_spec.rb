require 'spec_helper'

describe 'ssh::sshd_config_target' do
  let(:dropin) { '/etc/ssh/sshd_config.d/00-simp.conf' }

  in_sshd_config = [
    'AcceptEnv', 'AllowGroups', 'AllowUsers', 'DenyGroups', 'DenyUsers',
    'ListenAddress', 'Port', 'Ciphers', 'KexAlgorithms', 'MACs'
  ]
  first_wins = ['PermitRootLogin', 'X11Forwarding', 'UsePAM', 'MaxAuthTries', 'Banner']

  ['9', '10'].each do |major|
    context "on EL#{major}" do
      let(:facts) { { os: { 'release' => { 'major' => major } } } }

      first_wins.each do |key|
        it { is_expected.to run.with_params(key).and_return(dropin) }
      end

      in_sshd_config.each do |key|
        it { is_expected.to run.with_params(key).and_return(nil) }
      end

      it 'matches keywords regardless of case' do
        is_expected.to run.with_params('port').and_return(nil)
        is_expected.to run.with_params('permitrootlogin').and_return(dropin)
      end
    end
  end

  context 'on EL8' do
    let(:facts) { { os: { 'release' => { 'major' => '8' } } } }

    (first_wins + in_sshd_config).each do |key|
      it { is_expected.to run.with_params(key).and_return(nil) }
    end
  end

  context 'without an OS release fact' do
    let(:facts) { {} }

    it { is_expected.to run.with_params('PermitRootLogin').and_return(nil) }
  end
end
