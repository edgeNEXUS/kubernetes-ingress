package Edge::Manager::HTTPD::Extended::HTTPConnection::Writer;
use common::sense;
use Scalar::Util;

sub new {
    my ($class, $con) = @_;
    my $self = { con => $con };
    Scalar::Util::weaken($self->{con});

    bless $self, $class;
}

sub clean {
    my ($self) = @_;
    for (keys %$self) {
        delete $self->{$_};
    }
    %$self = ();
    undef $self;
    ()
}

sub con {
    my $con = $_[0]->{con};
    return undef if !defined ($con) ||
                    !defined ($con->{hdl}) ||
                    $con->{disconnected};
    $con
}

sub write {
    my $con = $_[0]->con or return 0;
    # make sure that the UTF-8 flag is off, otherwise AnyEvent will
    # complain
    utf8::downgrade $_[1];
    $con->{hdl}->push_write($_[1]);
    1
}

sub print { goto &write; }

sub close {
    my $con = $_[0]->con;

    # it's possible that current writer may keep any watchers/guards;
    # do not keep any watchers
    $_[0]->clean;

    return 0 unless $con;

    $con->response_done;
    1
}

sub DESTROY {
    return unless $_[0];
    $_[0]->close;
}

1;
