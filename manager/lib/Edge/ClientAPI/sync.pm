package Edge::ClientAPI::sync;
use common::sense;
use Edge::ClientAPI::async;
use Carp;
use AnyEvent;
use Data::Dumper;
#use Devel::GlobalDestruction;

$Carp::Internal{ (__PACKAGE__) } = 1;

sub new {
    my $class = shift;
    my $async = Edge::ClientAPI::async->new(@_);
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

for my $method (@methods) {
    no strict 'refs';

    *{ __PACKAGE__ . "::$method" } = sub {
        my ($self, @args) = @_;
        my (@results, @errors);

        my $cv = condvar AnyEvent;
        my @ret;

        $$self->$method(@args,
            sub {
                @ret = @_;
                $cv->send;
                ()
            }
        );

        $cv->recv;

        return @ret;
    };
}

#sub DESTROY {
#    my ($self) = @_;
#    return if in_global_destruction;
#}

1;
