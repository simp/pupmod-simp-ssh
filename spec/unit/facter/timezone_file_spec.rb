# frozen_string_literal: true

require 'spec_helper'
require 'facter'
require 'facter/timezone_file'

describe :timezone_file, type: :fact do
  subject(:fact) { Facter.fact(:timezone_file) }

  before :each do
    Facter.clear
    allow(File).to receive(:exist?).and_call_original
  end

  context 'on a Linux host' do
    before :each do
      allow(Facter.fact(:kernel)).to receive(:value).and_return('Linux')
    end

    context 'when /etc/localtime exists' do
      before :each do
        allow(File).to receive(:exist?).with('/etc/localtime').and_return(true)
      end

      it 'returns /etc/localtime' do
        expect(fact.value).to eq('/etc/localtime')
      end
    end

    context 'when /etc/localtime does not exist and timezone is set to America/New_York' do
      before :each do
        allow(Facter).to receive(:value).with('timezone').and_return('America/New_York')
        allow(File).to receive(:exist?).with('/etc/localtime').and_return(false)
      end

      context 'when /usr/share/zoneinfo/America/New_York exists' do
        before :each do
          allow(File).to receive(:exist?).with('/usr/share/zoneinfo/America/New_York').and_return(true)
        end

        it 'returns /usr/share/zoneinfo/America/New_York' do
          expect(fact.value).to eq('/usr/share/zoneinfo/America/New_York')
        end
      end

      context 'when /usr/share/zoneinfo/America/New_York does not exist' do
        before :each do
          allow(File).to receive(:exist?).with('/usr/share/zoneinfo/America/New_York').and_return(false)
        end

        it 'returns /usr/share/zoneinfo/UTC' do
          expect(fact.value).to eq('/usr/share/zoneinfo/UTC')
        end
      end
    end
  end

  context 'on a non-Linux host' do
    before :each do
      allow(Facter.fact(:kernel)).to receive(:value).and_return('windows')
    end

    it 'returns nil' do
      expect(fact.value).to be_nil
    end
  end
end
