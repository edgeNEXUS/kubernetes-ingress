#!/usr/bin/env perl
use common::sense;
use Test::More;
use Try::Tiny;
use Data::Dumper;
use YAML::Tiny;
use Coro;
use FindBin;
BEGIN { unshift @INC, '../lib' if $ENV{EDGE_DEVELOPER} }
use Edge::ClientAPI::Feed;
use Edge::ClientAPI::E;
use FindBin; use lib "$FindBin::Bin/../t/lib"; use EdgeTest;

sub Edge::ClientAPI::Feed::Config::HOOK_CERT_FILEPATHS($$) { # $cert_path,
                                                             # $key_path
    if ($_[0] eq "/etc/edgenexus-manager/secrets/echo-echo-secret" &&
        $_[1] eq "/etc/edgenexus-manager/secrets/echo-echo-secret") {

        pass "SSL cert and key paths re-assigned";
        $_[0] = "$FindBin::Bin/sample4-ssl/secret";
        $_[1] = "$FindBin::Bin/sample4-ssl/secret";
        return;
    }

    if ($_[0] eq "/etc/edgenexus-manager/secrets/echo-echo-secret2" &&
        $_[1] eq "/etc/edgenexus-manager/secrets/echo-echo-secret2") {

        pass "SSL cert and key paths re-assigned";
        $_[0] = "$FindBin::Bin/sample5-ssl/secret2";
        $_[1] = "$FindBin::Bin/sample5-ssl/secret2";
        return;
    }

    ()
}

my $creds = Edge::ClientAPI::Creds->new(user => EdgeTest::var('api_user'),
                                        pass => EdgeTest::var('api_pass'),
                                        host => EdgeTest::var('api_host'),
                                        port => EdgeTest::var('api_port'));

sub test_yaml($) {
    my $yaml_dir = shift;
    die "No yaml directory" unless length $yaml_dir;

    my $cv = AE::cv;

    async {
        my $feed = Edge::ClientAPI::Feed->new($creds, $yaml_dir);
        $feed->update_config;

        is ref $feed->config->data, 'HASH';
        try {
            $feed->process(sub {
                my ($cfg_version) = @_;
                is $cfg_version, 3, 'config version 3 applied';
            });
            pass "ADC configured";
        } catch {
            fail "ADC configured: $_";
        };

        $cv->send;
    };

    my $w = AE::timer 0, 1, sub {
        AE::log info => "Heartbeat %s", AE::time;
    };

    $cv->recv;
}

sub main() {
    my @yaml_dirs = (
        #"$FindBin::Bin/sample/",
        #"$FindBin::Bin/sample2/",
        #"$FindBin::Bin/sample3/",
        "$FindBin::Bin/sample4-ssl/"
        #"$FindBin::Bin/sample5-ssl/"
    );

    for my $dir (@yaml_dirs) {
        test_yaml $dir;
    }
}

main;
done_testing;
