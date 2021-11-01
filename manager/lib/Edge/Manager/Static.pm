package Edge::Manager::Static;
use common::sense;
use Cwd ();
use Data::Dumper;
use File::Spec;
use File::Temp;
use File::Path;
use AnyEvent::Log;
use Edge::Manager;

our $VERSION         = $Edge::Manager::VERSION;
our $STATIC_FALLBACK = 0;

{
    package static;
    use common::sense;

    # Fallback
    unless (exists &{static::find}) {
        *{static::find} = sub { };
        $Edge::Manager::Static::STATIC_FALLBACK = 1;
    }

    unless (exists &{static::list}) {
        *{static::list} = sub { };
        $Edge::Manager::Static::STATIC_FALLBACK = 1;
    };
}

my $APP_SHARE_DIR       = "share";
my $HTML5_PREFIX        = "/html5";
my $HTML5_FS_FULL_PATH  = undef;
my $TEMP_DIR            = undef;

sub _update();
#sub acme_dir();

sub init() {
    # Determine path to `share` directory.
    if ($STATIC_FALLBACK) {
        if ($Edge::Manager::DIST) {
            # Software is prepared to be installed somewhere.
            require File::ShareDir;
            $APP_SHARE_DIR = File::ShareDir::dist_dir('Edge-Manager');
        }
        else {
            # Software is running from local directory, most probably from
            # the source code repository.
            use FindBin;
            $APP_SHARE_DIR = "$FindBin::Bin/../share";
        }
    }
    else {
        # Keep default name for static.
    }

    _update;

    # Extract ACME to temp directory (if not already extracted somewhere)
    unless ($STATIC_FALLBACK) {

        my $dir = temp_dir();
        AE::log debug => "Extract share/acme to temp directory '$dir'...";

        for my $fn (static::list()) {
            next unless $fn =~ m!share/acme/!;
            AE::log trace => "Extract file '$fn' to '$dir/'...";

            my $abs = "$dir/$fn";

            # Create all directories in the path.
            my ($volume, $directories, $file) = File::Spec->splitpath("$abs");
            die "No volume expected in Unix-like system" if length $volume;
            File::Path::make_path($directories);

            # Write file and set 0755 attributes for .sh files of ACME
            open my $fh, '>', $abs or die "Couldn't write file $abs: $!";
            print $fh static::find($fn);
            chmod 0755, $fh if $fn =~ /\.sh$/;
            close $fh;
        }
    }

    # Test acme_dir()
    #unless (-d acme_dir && -e acme_dir . "/acme.sh") {
    #    die "No share directory with acme.sh program\n";
    #}

    # Test html5 file
    #unless (defined find_html5("/50x.tmpl")) {
    #    die "No html5 directory with all files\n";
    #}

    ()
}

sub share_dir() { $APP_SHARE_DIR }

sub temp_dir() {
    return $TEMP_DIR if defined $TEMP_DIR;

    # Do not use tmpfs directory as it may not allow to execute files.
    #return $TEMP_DIR = File::Temp::tempdir(DIR => "/var/tmp", CLEANUP => 1);
    # Create object File::Temp::Dir.
    return $TEMP_DIR = File::Temp->newdir(
        'edge-cert-mgr-XXXXXXXX',
        DIR => "/var/tmp",
        # File::Temp takes care to only remove those temp files created by a
        # particular process ID. This means that a child will not attempt to
        # remove temp files created by the parent process.
        CLEANUP => 1
    );
}

#sub acme_dir() {
#    if ($STATIC_FALLBACK) {
#        return share_dir . "/acme";
#    } else {
#        return temp_dir . "/" . share_dir . "/acme";
#    }
#}

sub html5_prefix(;$) {
    return $HTML5_PREFIX unless @_;
    $HTML5_PREFIX = $_[0];
    _update;
    ()
}

sub _update() {
    # logical cleanup of path
    $HTML5_FS_FULL_PATH = File::Spec->canonpath(
        $APP_SHARE_DIR . "/" . $HTML5_PREFIX);
    ()
}

sub html5_fs_full_path() {
    return $HTML5_FS_FULL_PATH;
}

sub find_html5 {
    my $uri_path = shift; # always begins with `/`
    my $name     = $HTML5_FS_FULL_PATH . $uri_path;

    AE::log trace => "Open file '%s'...", $name;

    unless ($STATIC_FALLBACK) {
        return static::find($name);
    }

    # try local file system
    open my $fh, '<', $name or return undef;
    binmode $fh;
    my $buf = do { local $/ = undef; <$fh> };
    close $fh;
    return $buf;
}

1;
