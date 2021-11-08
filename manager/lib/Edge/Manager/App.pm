package Edge::Manager::App;
use common::sense;
use Carp ();
use Getopt::Long ();
use File::Path ();
use Data::Dumper;
use Edge::Manager;
use Edge::Manager::Static;
use Edge::Manager::Watcher;
use Edge::Manager::Web;
use Edge::ClientAPI;
use Edge::ClientAPI::Logging;
$|++;

our $VERSION = $Edge::Manager::VERSION;

our $DEFAULT_API_PORT      = 28000;
our $DEFAULT_API_PWD_FILES = [ '/mnt/info/sec.txt', '/mnt/conf/sec.txt' ];
our $DEFAULT_PID_FILE      = '/var/lib/edgenexus-manager/manager.pid';
our $DEFAULT_CONFIG_DIR    = '/etc/edgenexus-manager';
our $DEFAULT_LOG_DIR       = '/var/log/edgenexus-manager';
our $DEFAULT_LIB_DIR       = '/var/lib/edgenexus-manager';

sub new {
    my $class = shift;
    bless { @_ }, $class;
}

sub host         {   $_[0]{host}         }
sub port         {   $_[0]{port}         }
sub hostname     {   $_[0]{hostname}     }
sub config_dir   {   $_[0]{config_dir}   } # Directory path that ends with '/'
sub log_dir      {   $_[0]{log_dir}      } # Directory path that ends with '/'
sub lib_dir      {   $_[0]{lib_dir}      } # Directory path that ends with '/'
sub pid_file     {   $_[0]{pid_file}     }
sub api_creds    {   $_[0]{api_creds}    }
sub test         { !!$_[0]{test}         }
sub no_auth_form { !!$_[0]{no_auth_form} }
sub is_debug     { Edge::ClientAPI::Logging::is_debug }

sub _api_auto($) {
    my $self = shift;
    AE::log info => "Determine ADC API settings...";

    my $address = `ip r s 0/0 |sed -e 's/.* via //' -e 's/ .*//'`;
    $address =~ s/\s+$//;

    $self->{api_host} = $address;
    $self->{api_port} = $DEFAULT_API_PORT;
    $self->{api_user} = `hostname`;
    $self->{api_user} =~ s/\s+$//;

    my ($fh, $ok);
    for my $fn (@$DEFAULT_API_PWD_FILES) {
        AE::log info  => "Try to obtain ADC API password";
        AE::log debug => "Open password file %s...", $fn;
        if (open $fh, '<', $fn) {
            AE::log debug => "Security file %s has been open", $fn;
            $ok = 1;
            last;
        }
    }

    if ($ok) {
        # Read password.
        $self->{api_pass} = <$fh>;
        $self->{api_pass} =~ s/\s+$//;
        close $fh;
    }

    unless (defined $self->{api_pass}) {
        AE::log warn => "Couldn't obtain ADC API password";
    } else {
        AE::log info => "Obtained ADC API password";
    }

    ()
}

sub process_signal_and_exit {
    my ($self) = @_;

    my $pid;
    if ($self->{signal} eq 'reload' || $self->{signal} eq 'quit') {
        open my $fh, '<', $self->pid_file
            or die sprintf "Couldn't open PID file '%s'' for reading: %s\n",
                           $self->{pid_file}, $!;
        $pid = <$fh>;
        close $fh;

        unless ($pid =~ /^\d+/) {
            AE::log error => "Couldn't read valid PID from file '%s'",
                             $self->{pid_file};
            exit -1;
        } else {
            $pid = int $pid;
        }
    }

    if ($self->{signal} eq 'reload') {
        AE::log info => "Sending HUP signal to main process (%d) of " .
                        "EdgeNEXUS Manager in order to reload it...", $pid;
        kill HUP => $pid;
        exit 0;
    }
    elsif ($self->{signal} eq 'quit') {
        AE::log info => "Sending QUIT signal to main process (%d) of " .
                        "EdgeNEXUS Manager for graceful shutdown...", $pid;
        kill QUIT => $pid;
        exit 0;
    }
    else {
        AE::log error => "Signal '%s' is not supported", $self->{signal};
        exit -1;
    }
}

sub write_pid_file {
    my ($self) = @_;

    open my $fh, '>', $self->{pid_file}
        or die "Couldn't open PID file '$self->{pid_file}' for writing: $!\n";
    print $fh $$, "\n";
    close $fh;
    ()
}

sub parse_options {
    my $self = shift;

    # edgenexus-ingress runs edgenexus-manager in the following way:
    # 1. `/edgenexus-manager -v`: to get version
    # 2. `/edgenexus-manager`: to run permanently manager, and balancer if it is
    #                          running in the same container.
    # 3. `/edgenexus-manager -s reload`: to apply changes on balancer.
    local @ARGV = @_;

    #if (1) {
    #    my $time = AE::time;
    #    my $fn   = "/tmp/edge-$$-$time.log";
    #    open my $fh, '>', $fn or die "Couldn't open file $fn: $!";
    #    print $fh Dumper+\@ARGV;
    #    close $fh;
    #}

    my $predefined_args = 0;
    unless (@ARGV) {
        # No arguments.
        # TODO: Just start and sleep. Provide with .sock files.


        $predefined_args = 1;
#        push @ARGV, qw(--port 8080
#                       --api-auto
#                       --no-auth-form
#                       --check-api
#                       --config /mnt/conf);

        @ARGV = qw(--hostname 192.168.2.125
                   --api-host 192.168.2.132
                   --api-port 443
                   --api-user=admin
                   --api-pass=jetnexus
                   --no-auth-form);
    }

    my $parser = Getopt::Long::Parser->new(
        config => [ "no_auto_abbrev", "no_ignore_case", "pass_through" ],
    );

    my %api;

    $parser->getoptions(
        #"host=s"     => \$self->{host},
        #"port=i"     => \$self->{port},

        "s|signal=s" => \$self->{signal},

        "hostname=s" => \$self->{hostname},
        "config-dir=s" => \$self->{config_dir},
        "log-dir=s"    => \$self->{log_dir},
        "lib-dir=s"    => \$self->{lib_dir},

        "p|pid-file=s" => \$self->{pid_file},

#        "api-auto|api_auto"   => sub { _api_auto($self) },
#        "api-host|api_host=s" => \$self->{api_host},
#        "api-port|api_port=i" => \$self->{api_port},
#        "api-user|api_user=s" => \$self->{api_user},
#        "api-pass|api_pass=s" => \$self->{api_pass},

#        "check-api|check_api"       => \$self->{check_api},
#        "no-auth-form|no-auth_form" => \$self->{no_auth_form},

        "h|help"     => \$self->{help},
        "v|version"  => \$self->{version},
        "t|test"     => \$self->{test},
    );

    if ($self->{help}) {
        require Pod::Usage;
        Pod::Usage::pod2usage(0);
    }

    my $version_line = "Edge::Manager $Edge::Manager::VERSION";
    if (length $Edge::Manager::GITTAG) {
        $version_line .= " (git tag $Edge::Manager::GITTAG)";
    }

    $version_line .= " Perl/$]"; # Add Perl version.

    if ($self->{version}) {
        # Show version for Ingress.
        # TODO: Get ADC version through API.
        #print "EdgeNEXUS version: edgenexus/4.8.2 (build 1895)\n";
        print $version_line, "\n";
        exit;
    }

    unless (length $self->config_dir) {
        $self->{config_dir} = $DEFAULT_CONFIG_DIR;
    }
    unless ($self->config_dir =~ m!/$!) {
        $self->{config_dir} .= "/";
    }
    unless (length $self->log_dir) {
        $self->{log_dir} = $DEFAULT_LOG_DIR;
    }
    unless ($self->log_dir =~ m!/$!) {
        $self->{log_dir} .= "/";
    }
    unless (length $self->lib_dir) {
        $self->{lib_dir} = $DEFAULT_LIB_DIR;
    }
    unless ($self->lib_dir =~ m!/$!) {
        $self->{lib_dir} .= "/";
    }

    unless (length $self->pid_file) {
        unless (length $self->lib_dir) {
            $self->{pid_file} = $DEFAULT_PID_FILE;
        } else {
            $self->{pid_file} = $self->lib_dir . "manager.pid";
        }
    }

    if (length $self->{signal}) {
        $self->process_signal_and_exit;
    }

    print "$version_line\n";

    if ($predefined_args) {
        AE::log info => "Use program arguments for container";
    }

    AE::log info => "Program arguments in use:\n%s",
                    join("\n", @ARGV);


    AE::log info => "%s started", $version_line;

#    # Note that certificate manager host will be validated by webserver.
#    # Default host is 0.0.0.0.
#    if (length $self->{port}) {
#        if ($self->{port} <= 0 || $self->{port} > 0xFFFF) {
#            AE::log fatal => "Invalid certificate manager port: %s",
#                             $self->{api_port};
#        }
#    }
#    else {
#        $self->{port} = 80; # Default.
#    }

#    unless (length $self->{hostname}) {
#        $self->{hostname} = `hostname`;
#        $self->{hostname} =~ s/\s+//g;
#
#        AE::log fatal => "Couldn't obtain hostname"
#            unless length $self->{hostname};
#    }

#    AE::log fatal => "Invalid application hostname"
#        if $self->{hostname} !~ /^[a-zA-Z0-9\.\-]+$/ ||
#           $self->{hostname} =~ /\s/;

    $Edge::ClientAPI::Logging::LOG_FILE = $self->log_dir . "manager.log";
    Edge::ClientAPI::Logging::enable_log_to_file();

    #for (keys %$self) {
    #    next unless /^api_(\w+)$/;
    #    next unless $self->{$_};
    #    $api{$1} = $self->{$_};
    #}

    my %api = (
        user => 'admin',     # Default username (to be changed by config files).
        pass => 'jetnexus',  # Default password (to be changed by config files).
        host => '127.0.0.1', # Host must be changed by config files.
        port => 443,         # Port cannot be changed by config files.
    );
    $self->{api_creds} = Edge::ClientAPI::Creds->new(%api);

    #AE::log info => "Edge::Manager IP: %s",   $self->host // '[all interfaces]';
    #AE::log info => "Edge::Manager Port: %d", $self->port;
    #AE::log info => "Edge::Manager Hostname: %s", $self->hostname;
    AE::log info => "Edge::Manager directory for config files: %s", $self->config_dir;
    AE::log info => "Edge::Manager directory for working files: %s", $self->lib_dir;
    AE::log info => "Edge::Manager directory for log files: %s", $self->log_dir;
    AE::log info => "Edge::Manager PID file: %s", $self->pid_file;
    #AE::log info => "ADC IP: %s",      $self->api_creds->host;
    #AE::log info => "ADC Port: %d",    $self->api_creds->port;
    #AE::log info => "ADC User: %s",    $self->api_creds->user // '[undef]';
    #AE::log info => "ADC Password: %s",
    #                $self->api_creds->has_pass ? "***" : '[undef]';

    ()
}

sub run {
    my $self = shift;

    my $is_debug = !!$ENV{EDGE_DEBUG};
    Edge::ClientAPI::Logging::setup($is_debug, sub {
        #Edge::Manager::Web::Logs::log_collect($_[0]);
        ()
    });

    unless (ref $self) {
        $self = $self->new;
        $self->parse_options(@_);
        return $self->run;
    }

    $self->write_pid_file
        unless $self->test;

    my @cond;
    # Setup it as soon as possible.
    my $sig_hup = AnyEvent->signal(signal => "HUP", cb => sub {
        AE::log info => "Signal HUP received to reload configs";
        Edge::Manager::Watcher::stop();
        push @cond, AE::time;
        ()
    });

    my $sig_quit = AnyEvent->signal(signal => "QUIT", cb => sub {
        AE::log info => "Signal QUIT received for graceful shutdown";
        Edge::Manager::Watcher::stop();
        exit 0;
        ()
    });

    Edge::Manager::Static::init;
    Edge::Manager::Static::html5_prefix("html5");

    AE::log info => "Share directory: %s", Edge::Manager::Static::share_dir;
    #AE::log info => "ACME directory: %s",  Edge::Manager::Static::acme_dir;
    AE::log info => "Web files directory: %s",
                    Edge::Manager::Static::html5_fs_full_path;

    unless ($] >= 5.022) {
        AE::log fatal => "Perl: Minimum version required 5.022 (yours is %s)",
                         $];
    }

    unless (-d $self->config_dir) {
        AE::log warn => "Directory for config files %s doesn't exist",
                        $self->config_dir;

        File::Path::mkpath($self->config_dir); # Dies if error.
    }

    if (1) {
        AE::log debug => "Test directory for config files...";
        my $fh;
        my $fn = $self->config_dir . ".test";
        unless (open $fh, '>', $fn) {
            AE::log error => "Couldn't write a test file to config " .
                             "files directory %s: %s", $self->config_dir, $!;
        }
        else {
            # All works. Remove test file.
            unlink $fn;
            close  $fh;
        }
    }

#    if ($self->{check_api}) {
#        AE::log info => "Get authorization on the ADC...";
#
#        my $cli = Edge::ClientAPI::sync($self->api_creds);
#        my @ret = $cli->authorize;
#
#        unless ($ret[1]{Success}) {
#            AE::log fatal => "Couldn't get authorized on the ADC: %s",
#                             $ret[1]{Detail};
#        }
#        AE::log info => "Edge::Manager get authorized on the ADC";
#    }

    #unless ($self->api_creds->ready_to_use) {
    #    if ($self->no_auth_form) {
    #        AE::log warn => "Not allowed to show auth form in web UI app " .
    #                        "to set API credentials (--allow-auth-form " .
    #                        "is not enabled)";
    #        $self->api_creds->ensure_ready_to_use; # Show error and die.
    #    }
    #}

    if ($self->test) {
        AE::log info => "Program dependencies and assets test has been done";
        exit 0;
    }

    Edge::Manager::Watcher::run($self, \@cond);
    Edge::Manager::Web::init($self);
    Edge::Manager::Web::run;

    ()
}

1;
