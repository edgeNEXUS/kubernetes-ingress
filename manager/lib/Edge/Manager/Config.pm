package Edge::Manager::Config;
use common::sense;
use Carp;
use AnyEvent::Log;
use Try::Tiny;
#use Config::Tiny;
#use File::Spec;
#use File::Path;
#use File::HomeDir::Dist;
use Data::Dumper;
use Safe::Isa;
use JSON::XS;
use AnyEvent::HTTP;
use Edge::Manager;
use Edge::ClientAPI;
use Edge::ClientAPI::E;

our $VERSION = $Edge::Manager::VERSION;
our $JSON    = JSON::XS->new->utf8->convert_blessed->pretty;
our $SINGLETON;

sub new {
    my ($class, $app, $datadir) = @_;

    die "Invalid app object"
        unless $app->$_isa('Edge::Manager::App');

    die "No config data directory"
        unless length $datadir;
    die "Config data directory must end with /"
        unless $datadir =~ m!/$!;

    my $self = { app => $app, api_creds => undef, datadir => $datadir };

    bless $self, $class;

    $self->api_creds($app->api_creds->clone);

    $SINGLETON = $self;
    return $self;
}

sub singleton {
    my ($class) = @_;
    die "No config singleton" unless $SINGLETON;
    return $SINGLETON;
}

sub app     { $_[0]{app} }
sub datadir { $_[0]{datadir} }

sub api_creds { # $self [, $api_cred ]
    my $self = shift;
    if (@_) {
        my $creds = shift;
        die "Invalid API creds object"
            unless $creds->$_isa('Edge::ClientAPI::Creds');
        $self->{api_creds} = $creds;
    }

    return $self->{api_creds};
}

sub get_data {
    my $self = shift;
    my $data = +{};
    my $fn   = $self->datadir . 'edge-cert-mgr.json';
    my $fh;

    $self->{_cached_data} = $data;

    unless (open $fh, '<', $fn) {
        if ($!{ENOENT}) {
            # File not found. Create it with empty data.
            $self->set_data($data);
            return;
        }

        AE::log warn => "Couldn't open config file %s: %s", $fn, $!;
        return $data;
    }

    my $buf = do { local $/ = undef; <$fh> };
    close $fh;

    return $data unless length $buf;

    try {
        $data = $JSON->decode($buf);
    } catch {
        AE::log crit => "Couldn't decode config file JSON: %s", $_;
    };

    $self->{_cached_data} = $data;
    return $data;
}

sub set_data {
    my ($self, $data) = @_;
    die "Config data is not hashref"
        unless ref $data;

    my $fn  = $self->datadir . 'edge-cert-mgr.json';
    my $fnt = sprintf "%s.%s.tmp", $fn, AE::time;
    my $buf = $JSON->encode($data);

    # Save to temporary file first.
    open my $fh, '>', $fnt or die $!;
    print $fh $buf;
    close $fh;

    rename $fnt, $fn or die $!;

    $self->{_cached_data} = $data;
    ()
}

sub cached_data {
    my $self = shift;
    unless ($self->{_cached_data}) {
        # Cache will be updated by this call.
        return $self->get_data;
    }
    return $self->{_cached_data};
}

sub save_cached_data {
    my $self = shift;
    $self->set_data($self->cached_data);
    ()
}

#sub guid { # $self [, $guid ]
#    my $self = shift;
#    if (@_) {
#        Edge::Manager::Data::validate_guid $_[0];
#        $self->{guid} = $_[0];
#    }
#
#    return $self->{guid}; # Can be undefined.
#}

sub validate_guid {
    my $self = shift;

    return $self->api_creds->guid
        if $self->api_creds->has_guid;

    if ($self->app->no_auth_form) {
        die e40_format EDGE_ERROR, "Not authorized (go to Settings and " .
                                   "provide valid ADC API credentials)";
    }

    $self->api_creds->ensure_ready_to_use;
    ()
}

#sub acme_dir {
#    my $self = shift;
#    return $self->datadir . "acme.sh";
#}

1;
