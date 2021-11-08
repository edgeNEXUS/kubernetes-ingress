
mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
current_dir := $(dir $(mkfile_path))

export STATICPERLRC=$(current_dir).staticperlrc

TARGET_APP  = bin/edgenexus-manager
TARGET_PERL = bin/perl

# Add here modules you need to bundle in `bin/app`.
TARGET_FLAGS=-MConfig_heavy.pl \
             -MAnyEvent::Impl::Perl \
             -Mutf8 \
             -Mcommon::sense \
             -MURI \
             -MURI::_foreign \
             -MNet::SSLeay \
             -MAnyEvent::HTTPD -MURI::http \
             -MAnyEvent::HTTP \
             -MAnyEvent::Tools \
             -MAnyEvent::Tools::Mutex \
             -MAnyEvent::ForkObject \
             -MData::StreamSerializer \
             -MData::StreamDeserializer \
             -MDigest::SHA \
             -MAnyEvent::Log \
             -MAnyEvent::Impl::EV \
             -MAnyEvent::IO \
             -MAnyEvent::IO::Perl \
             -MAnyEvent::IO \
             -MAnyEvent::DNS \
             -MAnyEvent::Loop \
             -MAnyEvent::Strict \
             -MAnyEvent::Socket \
             -MAnyEvent::Handle \
             -MAnyEvent::Util \
             -MAnyEvent::TLS \
             -MCoro \
             -MFile::Glob \
             -MJSON \
             -MAE \
             -MTime::Local \
             -MScalar::Util \
             -MAnyEvent \
             -MTry::Tiny \
             -MData::Dumper -MJSON::XS \
             -MMIME::Base64 \
             -MSafe::Isa \
             -MGetopt::Long \
             -MConfig::Tiny \
             -Mboolean \
             -MFile::Spec \
             -MCwd \
             -MFile::Temp \
             -MFindBin \
             -MYAML::Tiny \
             -MIO::Socket::SSL::Utils \
             -MCrypt::OpenSSL::PKCS12 \
             -Mlib

include $(current_dir)app.mk

all: prepare clean $(TARGET_PERL) $(TARGET_APP)

prepare:
	@mkdir -p bin

$(TARGET_APP):
	/staticperl/staticperl mkapp app -vv --boot ../bin/edgenexus-manager $(TARGET_FLAGS)
	@strip app
	@mv app $(TARGET_APP)
	@readelf -d $(TARGET_APP)

$(TARGET_PERL):
	/staticperl/staticperl mkperl -vv $(TARGET_FLAGS) $(TARGET_PERL_FLAGS)
	@strip perl
	@mv    perl bin/perl

clean:
	@rm -f bin/perl
	@rm -f $(TARGET_APP)
