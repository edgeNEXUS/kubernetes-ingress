package Edge::Manager::Watcher;
use common::sense;
use Data::Dumper;
use Try::Tiny;
use Safe::Isa;
use Coro;
use Edge::Manager;
use Edge::Manager::Static;
use Edge::Manager::Config;
use Edge::ClientAPI::Feed;

our $VERSION = $Edge::Manager::VERSION;
our $config_version = 0;
my $coro;
my $feed;

sub stop {
    AE::log info => "Stop existing feed...";
    if ($feed) {
        undef $feed;
    }
}

sub run {
    my ($app, $cond) = @_;
    die "Invalid app object" unless $app->$_isa('Edge::Manager::App');
    die "Invalid condition variable" unless ref $cond eq 'ARRAY';

    my $w;
    my $is_first_time = 1;

    # Watch cond var.
    $coro = async {
        while () {
            Coro::AnyEvent::sleep(1) unless $is_first_time;
            $is_first_time = 0;

            next unless @$cond;
            my $time = $cond->[-1]; # Take the latest.
            @$cond = ();

            AE::log info => "Received signal at %s GMT to update ADC config",
                            scalar gmtime($time);

            $w = AE::timer 0, 2, sub {
                AE::log info => "Heartbeat: %s", AE::time;
                ()
            };

            $feed = Edge::ClientAPI::Feed->new(
                            $app->api_creds,
                            $app->config_dir . 'config-version.yaml',
                            $app->config_dir . 'edge.yaml',
                            $app->config_dir . 'conf.d/');

            # Re-read YAML files and restart feeding process on every critical
            # error.
            $feed->process_until_done(sub { # Success.
                my ($cfg_version) = @_;
                $config_version = $cfg_version;
            });

            undef $w;
        }
    };

    AE::log info => "Watcher quits.";
    ()
}

1;
