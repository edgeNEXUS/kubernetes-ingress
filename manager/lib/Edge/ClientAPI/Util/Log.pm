package Edge::ClientAPI::Util::Log;
use common::sense;
use AnyEvent::Log;
use Data::Dumper;

our $original_fh;
our $buffer;
our $is_original_fh_from_buffer;

sub setup($;$$) {
    my $cb = $_[2];
    my $fh;

    my $dup_done = !!defined $_[0];
    if (defined $_[0]) {
        unless (open $fh, ">&", $_[0]) {
            warn "Couldn't dup file handle: $!\n";
            $dup_done = 0;
        }
    }

    $original_fh                = $fh;
    $is_original_fh_from_buffer = 0;

    $original_fh->autoflush(1) if $dup_done;

    $AnyEvent::Log::LOG->log_cb(sub {
        if (ref $cb eq 'CODE') {
            my $new = $cb->($_[0]);

            if (defined $new) {
                print $original_fh $new;
                return 0;
            }
        }

        print $original_fh $_[0] if $dup_done;

        0
    });

    tie $_[0], 'Edge::ClientAPI::Util::Log::Tie', level => $_[1]
        if $dup_done;
    ()
}

sub set_original_fh($) {
    if ("$original_fh" ne "$_[0]") {
        $is_original_fh_from_buffer = 0;
    }

    return $original_fh = $_[0];
}

sub get_original_fh() {
    $original_fh
}

sub has_buffer()                 { !!length $buffer }

sub buffer()                     { $buffer // ''    }

sub is_original_fh_from_buffer() { $is_original_fh_from_buffer }

sub flush_buffer() {
    die "Logging is not set up" unless defined $original_fh;

    if (is_original_fh_from_buffer) {
        return -2;
    }

    unless (has_buffer) {
        AE::log error => "No buffered logs to flush.";
        return -1;
    }

    print $original_fh $buffer;

    $buffer = '';

    0
}

package Edge::ClientAPI::Util::Log::Tie;
use common::sense;

sub TIEHANDLE {
    my ($class, %args) = @_;
    $args{level} //= 'error';
    bless \%args, $class
}

sub PRINT {
    my $self = shift;
    return unless $self;

    my $ctx = AnyEvent::Log::ctx ((caller)[0]);
    $ctx->log($self->{level} => join("", @_));
}

1;
