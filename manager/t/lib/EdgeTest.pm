package EdgeTest;
use common::sense;
use Test::More ();
use Edge::ClientAPI::Logging;

our $STORAGE = +{};
our $INCLUDE = 0;

sub vars_devops() {
    api_user => 'admin',
    api_pass => 'jetnexus',
    api_host => '127.0.0.1',
    api_port => 443,
}

sub vars_developer1() {
    api_user => 'admin',
    api_pass => 'jetnexus',
    api_host => '192.168.2.132',
    api_port => 443,
}

sub vars_docker() {
    api_user => 'admin',
    api_pass => 'jetnexus',
    api_host => '127.0.0.1',
    api_port => 8443,
}

sub apply_env_overrides(%args) {
    $args{api_user} = $ENV{EDGE_TEST_API_USER}
        if defined $ENV{EDGE_TEST_API_USER} && length $ENV{EDGE_TEST_API_USER};
    $args{api_pass} = $ENV{EDGE_TEST_API_PASS}
        if defined $ENV{EDGE_TEST_API_PASS} && length $ENV{EDGE_TEST_API_PASS};
    $args{api_host} = $ENV{EDGE_TEST_API_HOST}
        if defined $ENV{EDGE_TEST_API_HOST} && length $ENV{EDGE_TEST_API_HOST};
    $args{api_port} = $ENV{EDGE_TEST_API_PORT}
        if defined $ENV{EDGE_TEST_API_PORT} && length $ENV{EDGE_TEST_API_PORT};

    return %args;
}

sub vars() {
    # As per your need, you can add more Edge::CertMgr test environments for
    # tests located in `t/`. Set appropriate value in environment variable
    # `EDGE_TEST` and optionally override credentials with EDGE_TEST_API_* envs.
    return apply_env_overrides(vars_devops())
        if $ENV{EDGE_TEST} eq 'devops';
    return apply_env_overrides(vars_developer1())
        if $ENV{EDGE_TEST} eq 'developer1';
    return apply_env_overrides(vars_docker())
        if $ENV{EDGE_TEST} eq 'docker';

    die "Value not supported from EDGE_TEST environment variable: " .
        $ENV{EDGE_TEST}
        if length $ENV{EDGE_TEST};

    # Test vars are empty to test Edge::CertMgr. Stop testing.
    # If your test doesn't call EdgeTest::vars() or EdgeTest::var(),
    # this error doesn't occur. Note that after `skip_all`, the test exits
    # with exit code 0.
    Test::More::plan skip_all => 'Test irrelevant if environment variable ' .
                                 'EDGE_TEST is not set. ' .
                                 'Please read t/lib/EdgeTest.pm for details.';

    die "Not expected to be here after `plan skip_all => ...`";
}

sub var($) {
    my $var  = shift; # e.g. `username`, `ip`, etc.
    my %vars = vars;
    return $vars{$var};
}

sub storage()   { $STORAGE }
sub include(;$) { @_ ? ($INCLUDE = !!$_[0]) : $INCLUDE }

Edge::ClientAPI::Logging::setup(0);

1;
