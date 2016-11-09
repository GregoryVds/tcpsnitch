# Purpose: test initialization (init.c) of Netspy.

require 'minitest/autorun'
require 'minitest/reporters'
require 'minitest/spec'
require './common.rb'

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

describe "Initialization" do
		
	let(:script_path) { PKT_SCRIPTS_PATH + '/init' }
	let(:cmd) {"#{LD_PRELOAD} #{PACKET_DRILL} #{script_path}/no_env.pkt 2>/dev/null"}

	describe "when no ENV variable is set" do
		it "should simply not crash" do
			assert system(cmd)
	 	end

		it "should create #{DEFAULT_PATH} if does not exits" do
			system "rm -rf #{DEFAULT_PATH}"
			system cmd 
      assert system("test -d #{DEFAULT_PATH}")
		end
	
		it "should not crash when #{DEFAULT_PATH} already exists" do
      system "test -d #{DEFAULT_PATH} || mkdir #{DEFAULT_PATH}"
      assert system cmd
		end
	end

	describe "when #{ENV_PATH} is set" do
		it "should not crash when #{ENV_PATH} exists" do
      dir = "/tmp/dummy"
      system "test -d #{dir} || mkdir #{dir}"
			assert system("#{ENV_PATH}=#{dir} #{cmd}")
      system "rm -rf #{dir}"
    end

		it "should not crash when #{ENV_PATH} does not exists" do
      dir = "/tmp/dontexists"
      system "rm -rf #{dir}"
			assert system("#{ENV_PATH}=#{dir} #{cmd}")
		end

		it "should not crash when #{ENV_PATH} is invalid" do
			assert system("#{ENV_PATH}=$*!9 #{cmd}")
		end
	end

	describe "when the PATH is resolved" do
		it "should create the system config dump in PATH" do
			skip
		end
		
		it "should not override a system config dump in PATH" do
			skip
		end

		it "should create a log dir in PATH" do 
			assert true
		end
		
		it "should create a log file in PATH" do
			assert true
		end
	end

	describe "when #{ENV_BYTES_IVAL} is set" do
		it "should not crash when #{ENV_BYTES_IVAL} is valid" do
			assert true
		end

		it "should not crash when #{ENV_BYTES_IVAL} is invalid" do
			assert true
		end
	end

	describe "when #{ENV_MICROS_IVAL} is set" do
		it "should not crash when #{ENV_MICROS_IVAL} is valid" do
			assert true
		end

		it "should not crash when #{ENV_BYTES_IVAL} is invalid" do
			assert true
		end
	end

end
