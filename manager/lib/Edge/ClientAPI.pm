package Edge::ClientAPI;
use strict;
use warnings;
BEGIN { our $VERSION = '1.01' }
use Carp;
use Data::Dumper;
use Edge::ClientAPI::Data;
use Edge::ClientAPI::async;
use Edge::ClientAPI::sync;
use Edge::ClientAPI::Object;
use Edge::ClientAPI::E
    EDGE_SUCCESS => [ 0000, "Success" ],
    EDGE_ERROR   => [ 6000, "%s" ],
;

$Carp::Internal{ (__PACKAGE__) } = 1;

sub async {
    no warnings 'redefine';
    *async = sub {
        return Edge::ClientAPI::async->new(@_);
    };
    goto \&async;
}

sub sync {
    no warnings 'redefine';
    *sync = sub {
        return Edge::ClientAPI::sync->new(@_);
    };
    goto \&sync;
}

1;
