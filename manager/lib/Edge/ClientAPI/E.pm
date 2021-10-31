package Edge::ClientAPI::E; # `E` is shortcut for Errors
use strict;
use warnings;
use Carp;
use Scalar::Util qw(blessed);

use overload (
    '""'  => \&as_string,
    '0+'  => \&as_number,

    fallback => 1,
);

our @ISA    = qw(Exporter);
our @EXPORT = qw(e40 e40_format is_e is_e40);
our $EXTRAS;

sub _is_format($) {
    my $from = 0;

    while (defined $_[0] && $from < length $_[0]) {
        my $pos = index $_[0], '%', $from;

        return '' if $pos == -1;

        $from = $pos + 1;
        $pos = index $_[0], '%', $from;

        return 1 if $pos != $from;


        $from = $pos + 1;
    }

    return '';
}

sub import {
    my $class = shift;
    my $CONSTANTS;

    my $size = @_ - 1;

    for (my $i = 0; $i < $size; $i += 2) {

        my $constant = $_[$i];
        my $value    = $_[$i + 1];

        my ($code, $detail) = @$value;

        if ($code !~ /^\d+$/) {
            die "Error code `$code` is not an integer";
        }

        if (exists $EXTRAS->{$code}) {
            die "Error code `$code' is already used",
                length $EXTRAS->{$code}{detail}
                          ? (" with detail: `$EXTRAS->{$code}{detail}'")
                          : ();
        }

        if (exists $CONSTANTS->{$constant}) {
            my $old_code = $CONSTANTS->{$constant};

            die "Error constant `$constant' is already used - ",
                "its code is `$old_code'",
                length $EXTRAS->{$old_code}{detail}
                          ? ("and detail is `$EXTRAS->{$old_code}{detail}'")
                          : ();
        }

        $CONSTANTS->{$constant} = int $code;
        $EXTRAS->{$code}        = { detail => $detail,
                                    format => _is_format($detail) };
    }

    if ($CONSTANTS) {
        eval q{ use constant $CONSTANTS; };
        push @EXPORT, keys %$CONSTANTS;
    }

    $class->export_to_level(1, $class, @EXPORT);

    ()
}

sub _e($$) { # $type, $code
    my $extras = $EXTRAS->{ $_[1] };

    bless {
        type   => int $_[0],
        code   => int $_[1],
        known  => !! $extras,

        detail =>   $extras && $extras->{detail},
        format => !!$extras && $extras->{format},
    }
}

sub e($$) { # $type, $code
    Carp::croak "Invalid error type"
        unless defined $_[0] && $_[0] == 40;

    Carp::croak "Invalid error code (must an integer)"
        unless $_[1] =~ /^\d+$/;

    return _e(int $_[0], int $_[1]);
}

sub e40($) { # $self, $code
    my $e = _e 40, $_[0];

    if ($e->{format}) {
        Carp::croak("use e40_format() instead to format detail with " .
                    "format specifiction (code: $_[0])");
    }
    return $e;
}

sub e40_format($$;@) { # $code [, $arg1, $arg2, ... ]
    my $code = shift;
    my $e    = _e 40, $code;

    unless ($e->{format}) {
        Carp::croak("e40_format() cannot format due to detail without " .
                    "format specification (code: $code)");
    }

    $e->{detail} = sprintf $e->{detail}, @_;

    return $e;
}

sub is_e(;$)      { # [ $e ] otherwise $_
    blessed( @_ ? $_[0] : $_ )            or return '';
    ( @_ ? $_[0] : $_ )->isa(__PACKAGE__) or return '';
    1
}

sub is_e40(;$)    { # [ $e ] otherwise $_
    blessed( @_ ? $_[0] : $_ )            or return '';
    ( @_ ? $_[0] : $_ )->isa(__PACKAGE__) or return '';

    ( @_ ? $_[0] : $_ )->{type} == 40
}

sub as_string  {
    defined $_[0]{detail} or return '';

    #if ($_[0]{format}) {
    #    return sprintf $_[0]{detail}, @{ $_[0]{format} };
    #}

    $_[0]{detail}
}

sub as_hashref {
    return { code   => $_[0]{code},
             type   => $_[0]{type},
             detail => $_[0]{detail} };
}

sub as_number  {  $_[0]{code}      }
sub detail     {  $_[0]{detail}    }
sub code       {  $_[0]{code}      }

sub type { # $self [, $new_type ]
    if (@_ >= 2) {
        if (defined $_[1] && $_[1] == 40) {
            return $_[0]{type} = 0+$_[1];
        }
        croak "Invalid error type";
    }

    $_[0]{type}
}

1;
