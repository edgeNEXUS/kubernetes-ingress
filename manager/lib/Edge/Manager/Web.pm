package Edge::Manager::Web;
use common::sense;
use Data::Dumper;
use Try::Tiny;
use Safe::Isa;
use Edge::Manager;
use Edge::ClientAPI::Logging;
use Edge::Manager::Static;
use Edge::Manager::Config;
use Edge::Manager::HTTPD::Extended;

our $VERSION = $Edge::Manager::VERSION;

our @httpds;
our $config;
our %apps;
our %requests;

sub init_httpd($$$) {
    my ($app, $host, $port) = @_;

    # To run unix socket, use $host as "unix/" and port as path (absolute).
    my $httpd = try {
        Edge::Manager::HTTPD::Extended->new(host => $host,
                                            port => $port);
    } catch {
        warn $_;
        undef
    };

    AE::log fatal => "Couldn't start Edge::Manager web server" unless $httpd;

    $httpd->{_DEBUG} = Edge::ClientAPI::Logging::is_debug;

    $httpd->reg_cb(request => sub {
        my ($httpd, $req) = @_;
        my $url      = $req->url;
        my @segments = $url->path_segments;

        return if @segments >= 1 && $segments[0] == '';

        $req->respond_404($req);
        $httpd->stop_request;
        ()
    });

    return $httpd;
}

sub init_config_httpd_routing($$) {
    my ($httpd, $app) = @_;

    AE::log fatal => "Invalid app object"
        unless $app->$_isa('Edge::Manager::App');

    #$apps{index} = new Edge::Manager::Web::Index;

    %requests = (
        '' => sub {
            my ($httpd_, $req) = @_;
            $req->respond_404($req);
            $httpd_->stop_request;
        },

        '/configVersion' => sub {
            my ($httpd_, $req) = @_;
            AE::log info => "Received request to return version of applied " .
                            "YAML config";

            AE::log info => "Return config version: %s",
                            $Edge::Manager::Watcher::config_version;

            $req->respond([ 200 => "OK",
                            { 'Content-Type' => 'text/plain' },
                            $Edge::Manager::Watcher::config_version ]);

            $httpd_->stop_request;
            ()
        },
    );

    $httpd->request_cb(%requests);
    ()
}

sub init($) {
    my ($app) = @_;

    AE::log fatal => "Invalid app object"
        unless $app->$_isa('Edge::Manager::App');

    # Set API creds for web server that were provided in command line.
    $config = Edge::Manager::Config->new($app, $app->config_dir);

    # To test unix socket webserver:
    # curl --unix-socket /var/lib/edgenexus-manager/edge-config-version.sock http://blah/configVersion
    my $httpd = init_httpd
           $app, "unix/", $app->lib_dir . "edge-config-version.sock";

    init_config_httpd_routing $httpd, $app;

    AE::log info => "Listening on %s:%s", $httpd->host, $httpd->port;

    push @httpds, $httpd;
    ()
}

sub run() {
    my $health = 0;
    my $w = AE::timer 5, 5, sub {
        # Run health check every 5 seconds.
        $health++;
        $health = 0 if $health == 0xFFFFFFFF;
    };

    AE::log fatal => "Web service(s) not initialized" unless @httpds;
    AE::log info  => "Web service(s) initialized";
    AE::cv->recv;
    AE::log info => "App quits.";
    ()
}

1;
