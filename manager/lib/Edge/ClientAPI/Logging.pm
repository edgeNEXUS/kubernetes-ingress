package Edge::ClientAPI::Logging;
use common::sense;
use Scalar::Util;
use POSIX ();
use Edge::ClientAPI::Util::Log;

our $VERSION = $Edge::ClientAPI::VERSION;
our $LOG_FILE //= "edge-client-api.log";

my ($is_debug, $is_trace, $level) = (0, 0, 'info');

sub is_debug() { $is_debug }
sub is_trace() { $is_trace }

sub setup {
    my $debug = !!shift;
    my $cb    = shift;

    Edge::ClientAPI::Util::Log::setup(*STDERR, 'error', $cb);

    $is_debug = !!($ENV{EDGE_DEBUG} || $ENV{EDGE_TRACE} || $debug);
    $is_trace = !!($ENV{EDGE_TRACE});

    if ($is_trace) {
        $level = 'trace'; # means 'debug' also
    } elsif ($is_debug) {
        $level = 'debug';
    } else {
        $level = 'info';
    }

    $AnyEvent::Log::FILTER->level($level);

    ()
}

sub enable_log_to_file() {
    die "No log file path" unless length $LOG_FILE;
    my $fh;
    unless (open $fh, '>>', $LOG_FILE) {
        AE::log error => "Couldn't open log file %s for writing: %s; " .
                         "skip logging to file", $LOG_FILE, $!;
        return;
    }

    close $fh;

    # All logs to be put in file including trace.
    $AnyEvent::Log::COLLECT->attach (
       new AnyEvent::Log::Ctx log_to_file => $LOG_FILE);
    ()
}

sub AnyEvent::Log::default_format($$$$) { # $time, $ctx, $lvl, $msg
    our ($now_int, $now_str);

    if ($_[3] =~ /^autoloaded model/i) {
        return undef;
    }

    my $ts = do {
        my $i = int $_[0];

        if ($now_int != $i) {
            $now_int = $i;
            $now_str = POSIX::strftime "%Y-%m-%d %H:%M:%S %z", localtime $i;
        }

        $now_str
    };

    my $pkg = $_[1][0];
    $pkg =~ s!:+!/!g;
    $pkg = lc $pkg;
    $pkg =~ s!anyevent!event!g;
    $pkg =~ s!carp!logging!g;

    my $ct = " ";
    my @res;

    for (split /\n/, sprintf "[%d] [%-5s] %s: %s", $$, $AnyEvent::Log::LEVEL2STR[$_[2]], $pkg, $_[3]) {
        push @res, "$ts$ct$_\n";
        $ct = " + ";
    }

    join "", @res
}

sub level(;$) {
    my $new_level  = shift;
    my $prev_level = $level;

    if (length $new_level) {
        $AnyEvent::Log::FILTER->level($new_level);
    }

    return $prev_level;
}

1;
