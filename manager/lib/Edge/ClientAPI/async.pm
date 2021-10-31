package Edge::ClientAPI::async;
use common::sense;
use Data::Dumper;
use Carp;
use Try::Tiny;
use AnyEvent;
use AnyEvent::Util;
use AnyEvent::Log;
use Scalar::Util;
use Safe::Isa;
use Edge::ClientAPI::Creds;
use Edge::ClientAPI::Request;
use Edge::ClientAPI::E;

$Carp::Internal{ (__PACKAGE__) } = 1;

our $TIMEOUT = 120;
our $VERSION = $Edge::ClientAPI::VERSION;

sub new {
    my ($class, @args) = @_;

    my $api_creds;
    if (@args == 1) {
        # Get API creds.
        $api_creds = $args[0];
        die "Invalid API creds object"
            unless $api_creds->$_isa('Edge::ClientAPI::Creds');
    }
    else {
        # Make API creds from args (like `host => '127.0.0.1', user => ..., `)
        $api_creds = Edge::ClientAPI::Creds->new(@args);
    }

    $api_creds->ensure_ready_to_use;

    my $self = bless { creds => $api_creds }, $class;

    $self->{http}{timeout}    = $TIMEOUT;
    $self->{http}{on_prepare} = sub { $TIMEOUT }; # Connection timeout.

    $self->{w} = []; # To store watchers here.

    $self
}

sub creds { $_[0]{creds} }

sub watcher_push { # $self, $w
    my $self = shift;

    for (@{$self->{w}}) {
        next if defined $_;
        $_ = $_[0];
        return;
    }

    # Must be a strong reference. Then $w (of caller) can be weak.
    push @{$self->{w}}, $_[0];
    ()
}

sub DESTROY {
    my ($self) = @_;

    # Sometimes quicker way to destroy watchers.
    undef $_ for @{$self->{w}};
    $self->{w} = undef;
    ()
}

# ------------------------------------------------------------------------------
# The below wraps functions of Edge::ClientAPI::Request to methods of
# Edge::ClientAPI::async.
#
# Therefore, we can have less code and implement some automation for some
# API methods, like automated authorization, if there is no GUID. Just in one
# client API call by user of this class.
# ------------------------------------------------------------------------------
for my $method (@{Edge::ClientAPI::Request::METHODS}) {
    no strict 'refs';

    next if $method eq 'authorize';

    *{ __PACKAGE__ . "::$method" } = sub { # $self [, @args ], $cb
        my $cb = pop @_;
        my ($self, @args) = @_;
        Scalar::Util::weaken($self);

        # TODO: Is there a need in getting IP? See alb_api.pm:
        #  # sub get_alb_api_url {
        #  #    my ($ConfigIP, $SecureConfig, $SecureConfigPort, $ConfigPort);
        #  #    my ($url, $port, $proto);
        #  #
        #  #    $port = '8081';
        #  #    $proto = 'http';
        #  #    $ConfigIP = '127.0.0.1';
        #  #  ...

        # (1): If there is no GUID, try to make authorization using user and
        # password in automated way.
        unless ($self->creds->guid) {
            return $self->authorize(sub {
                return unless $self;
                $self->creds->guid ? $self->$method(@args, $cb) : $cb->(@_);
                ()
            });
        }

        # (2): This is what this wrapper is mainly about - to store watcher.
        # If this class gets destroyed, all I/O operations will be cancelled.
        my $w = &{'Edge::ClientAPI::Request' . "::$method"}(
                    $self->creds, @args, $cb);

        $self->watcher_push($w);
        ()
    };
}

sub authorize {
    my ($self, $cb) = @_;
    Scalar::Util::weaken($self);

    my $w = Edge::ClientAPI::Request::authorize(
                $self->creds, sub {
        return unless $self;
        my ($guid, $hdr) = @_;

        # Store valid GUID. New requests can be performed without authorization.
        $self->creds->guid($guid) if $hdr->{Success};

        $cb->($guid, $hdr);
        ()
    });

    $self->watcher_push($w);
    ()
}

# ------------------------------------------------------------------------------
# Write advanced API requests here (based on multiple requests)
# ------------------------------------------------------------------------------
sub ADV_import_ssl_cert {
    my ($self, $cert_name, $binary, $pwd, $cb) = @_;

    # Have to make GET/19 before POST/19 (says alb_api.pm)
    my $w1 = $self->get_all_certificates(sub {
        my ($json, $hdr) = @_;
        unless ($hdr->{Success}) {
            $cb->(@_);
            return;
        }

        my $w2 = $self->import_ssl_cert($cert_name, $binary, $pwd, $cb);
        $self->watcher_push($w2);
        ()
    });

    $self->watcher_push($w1);
    ()
}

sub ADV_upload_flight_path_config {
    my ($self, $config, $cb) = @_;

    # This is a fake GET request before POST for avoiding the
    # 'Another user has made changes' issue
    my $w1 = $self->fake_request(sub {
        my ($json, $hdr) = @_;
        unless ($hdr->{Success}) {
            $cb->(@_);
            return;
        }

        my $w2 = $self->upload_flight_path_config($config, $cb);
        $self->watcher_push($w2);
        ()
    });

    $self->watcher_push($w1);
    ()
}

sub ADV_upload_acme_flight_path_config {
    my ($self, $config, $cb) = @_;

    my $w1 = $self->download_conf(sub {
        my ($orig_conf, $hdr) = @_;
        unless ($hdr->{Success}) {
            $cb->(@_);
            return;
        }

        # Ensure there is no already acme-challenge in flightPATH config.
        # TODO: parse config and check condition section:
        #     [jetnexusdaemon-Path-3500-Condition-1]
        if ($orig_conf =~ m!Value="well-known/acme-challenge"!) {
            AE::log info => "Condition for 'well-known/acme-challenge' is already configured in flightPATH";
            $cb->(undef, $hdr);
            return;
        }

        my $w2 = $self->ADV_upload_flight_path_config($config, $cb);
        $self->watcher_push($w2);
        ()
    });

    $self->watcher_push($w1);
    ()
}

sub ADV_get_ssl_cert_details {
    my ($self, $name, $cb) = @_;

    # Have to make GET/19 before POST/19 (says alb_api.pm)
    my $w1 = $self->get_all_certificates(sub {
        my ($json, $hdr) = @_;
        unless ($hdr->{Success}) {
            $cb->(@_);
            return;
        }

        my $w2 = $self->get_ssl_cert_details($name, $cb);
        $self->watcher_push($w2);
        ()
    });

    $self->watcher_push($w1);
    ()
}

sub ADV_remove_ssl_cert {
    my ($self, $name, $cb) = @_;

    # Have to make GET/19 before POST/19 (says alb_api.pm)
    my $w1 = $self->get_all_certificates(sub {
        my ($json, $hdr) = @_;
        unless ($hdr->{Success}) {
            $cb->(@_);
            return;
        }

        my $w2 = $self->remove_ssl_cert($name, $cb);
        $self->watcher_push($w2);
        ()
    });

    $self->watcher_push($w1);
    ()
}

1;
