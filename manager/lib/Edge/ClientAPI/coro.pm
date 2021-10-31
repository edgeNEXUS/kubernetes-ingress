package Edge::ClientAPI::coro;
use common::sense;
use Edge::ClientAPI::async;
use Carp;
use AnyEvent;
use Data::Dumper;

$Carp::Internal{ (__PACKAGE__) } = 1;

our $VERSION = $Edge::ClientAPI::VERSION;

sub new {
    my $class = shift;
    my @args  = @_;
    my $async = Edge::ClientAPI::async->new(@args);
    return bless \ $async, $class;
}

sub creds { my $self = shift; $$self->creds(@_) }

my @methods = @{Edge::ClientAPI::Request::METHODS};
# TODO: Automate it.
push @methods, qw(
    ADV_import_ssl_cert
    ADV_get_ssl_cert_details
    ADV_upload_flight_path_config
    ADV_upload_acme_flight_path_config
    ADV_remove_ssl_cert
);

eval q{ require Coro };

for my $method (@methods) {
    no strict 'refs';

    *{ __PACKAGE__ . "::$method" } = sub {
        my ($self, @args) = @_;
        my (@results, @errors);

        my $cb = Coro::rouse_cb();

        $$self->$method(@args, $cb);
        my @ret = Coro::rouse_wait();
        return @ret;
    };
}

1;
