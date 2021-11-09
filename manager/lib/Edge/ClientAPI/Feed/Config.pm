package Edge::ClientAPI::Feed::Config;
use common::sense;
use Try::Tiny;
use YAML::Tiny;
use Data::Dumper;
use Safe::Isa;
use Digest::SHA;
use Edge::ClientAPI::Feed::FPS;
use Edge::ClientAPI::Feed::TLSS;
use Edge::ClientAPI::Feed::VSS_FPS;
use Edge::ClientAPI::E
    API_FEED_INVALID_YAML_INPUT => [ 5750, "Input YAML input (use file name or data reference)" ],
    API_FEED_INVALID_YAML_DATA  => [ 5751, "Input YAML data (must be a hash)" ],
    API_FEED_INVALID_YAML_SERVICES => [ 5752, "Invalid services (must be an array)" ],
    API_FEED_INVALID_YAML_UPSTREAMS => [ 5753, "Invalid upstreams (must be an array)" ],
;

sub __read_file($);
sub __read_yaml(\@);

sub new {
    my ($class, $input) = @_;
    my $yaml = __read_yaml @$input;
    my $self = bless { yaml => $yaml }, $class;
    return $self;
}

sub data  { $_[0]{yaml}[0] }
sub data_services  { $_[0]->data->{services}  } # Arrayref (can be empty).
sub data_upstreams { $_[0]->data->{upstreams} } # Arrayref (can be empty).

sub data_balancer_ip   { $_[0]->data->{balancer_ip}   } # Always defined.
sub data_balancer_user { $_[0]->data->{balancer_user} } # Always defined.
sub data_balancer_pass { $_[0]->data->{balancer_pass} } # Always defined.
sub data_external_ip   { $_[0]->data->{external_ip}   } # Always defined.

sub build_required_vss_fps {
    my ($self) = @_;

    my $vss_array = $self->_get_unique_vss_to_run;
    unless ($vss_array) {
        AE::log info => "No VSs to set on the balancer";
        return undef;
    }

    my $vss_fps = Edge::ClientAPI::Feed::VSS_FPS->new;
    for (@$vss_array) {
        my ($vs_ip, $vs_port) = @$_;
        my $fps  = Edge::ClientAPI::Feed::FPS->new($self, $vs_ip, $vs_port);
        my $tlss = Edge::ClientAPI::Feed::TLSS->new($self, $vs_ip, $vs_port);
        $vss_fps->add($vs_ip, $vs_port, $fps, $tlss);
    }

    return $vss_fps;
}

sub get_upstream_by_name {
    my ($self, $name) = @_;
    Scalar::Util::weaken($self);

    die "No upstream name in arguments" unless length $name;
    my $upstreams = $self->data_upstreams;

    my $found;
    for (@$upstreams) {
        if ($_->{name} eq $name) {
            return $_;
        }
    }

    return undef;
}

sub _get_unique_vss_to_run {
    my ($self) = @_;

    my $services    = $self->data_services;
    my $external_ip = $self->data_external_ip;

    my @vss_array;
    my %uniq;

    for my $service (@$services) {
        # Go through one service that contains own hostname, HTTP/HTTPS
        # listeners, and one SSL certificate (if HTTPS).
        my $listeners = $service->{listeners};

        if ($listeners && @$listeners) {
            for my $lst (@$listeners) {
                my $port = $lst->{port};
                next unless $port > 0 && $port <= 0xFFFF;
                my $ip = $lst->{address};
                $ip = $external_ip unless length $ip;
                $uniq{"$ip:$port"} = [ $ip, $port ];
            }
        }

        if ($service->{ssl} && $service->{ssl}{listeners}) {
            my $ssl_listeners = $service->{ssl}{listeners};
            next unless @$ssl_listeners;

            # Collect listeners.
            for my $lst (@$ssl_listeners) {
                my $port = $lst->{port};
                next unless $port > 0 && $port <= 0xFFFF;
                my $ip = $lst->{address};
                $ip = $external_ip unless length $ip;
                $uniq{"$ip:$port"} = [ $ip, $port ];
            }
        }
    }

    return undef unless %uniq;

    for (sort keys %uniq) {
        push @vss_array, $uniq{$_}; # [ IP, PORT ]
    }

    return \@vss_array;
}

sub __read_yaml(\@) {
    my ($input) = @_;

    my $data;
    for (@$input) {
        if (ref $_ eq 'SCALAR') {
            # String data.
            $data .= "\n" . $$_;
        } elsif (!ref $_) {
            # File or directory path.
            if (m!/$!) {
                # Directory path. Get all files in directory and read them.
                my @files = <$_*.yaml>;
                for my $filepath (@files) {
                    AE::log info => "Open EdgeNEXUS Manager config file: %s",
                                    $filepath;
                    $data .= "\n---\n";
                    $data .= __read_file $filepath;
                }
            } else {
                # File path.
                AE::log info => "Open EdgeNEXUS Manager config file: %s", $_;
                $data .= "\n---\n";
                $data .= __read_file $_;
            }
        }
        else {
            die e40 API_FEED_INVALID_YAML_INPUT;
        }
    }

    AE::log info => "Config %s", $data;

    my $yaml = +{};
    my $yaml = YAML::Tiny->read_string($data); # Data can be empty.
    unless ($yaml) {
        die e40 API_FEED_INVALID_YAML_DATA;
    }

    # Merge all in one.
    for (my $i = 1; $i < @$yaml; $i++) {
        my $el = $yaml->[$i];
        next unless ref $el eq 'HASH';
        for my $key (sort keys %$el) {
            my $val = $el->{$key};
            if ($key eq 'services' || $key eq 'upstreams') {
                # Merge arrays.
                next unless ref $val eq 'ARRAY';
                for my $copy_el (@$val) {
                    push @{$yaml->[0]->{$key}}, $copy_el;
                }
            }
            elsif ($key eq 'config') {
                # Config hash.
                $yaml->[0]->{config} = $val;
            }
            elsif (!ref $val) {
                # Strings.
                $yaml->[0]->{$key} = $val;
            }
            else {
                # Ignore such value.
            }
        }

        $yaml->[$i] = undef;
    }

    unless (defined $yaml->[0]{services}) {
        # It is allowed that no `services` are defined.
        $yaml->[0]{services} = [];
    }
    elsif (ref $yaml->[0]{services} ne 'ARRAY') {
        die e40 API_FEED_INVALID_YAML_SERVICES;
    }

    unless (defined $yaml->[0]{upstreams}) {
        # It is allowed that no `upstreams` are defined.
        $yaml->[0]{upstreams} = [];
    }
    elsif (ref $yaml->[0]{upstreams} ne 'ARRAY') {
        die e40 API_FEED_INVALID_YAML_UPSTREAMS;
    }

    unless (length $yaml->[0]{balancer_ip}) {
        $yaml->[0]{balancer_ip} = "127.0.0.1"; # Dummy value.
    }
    unless (length $yaml->[0]{balancer_user}) {
        $yaml->[0]{balancer_user} = "admin"; # Initial value.
    }
    unless (length $yaml->[0]{balancer_pass}) {
        $yaml->[0]{balancer_pass} = "jetnexus"; # Initial value.
    }
    unless (length $yaml->[0]{external_ip}) {
        $yaml->[0]{external_ip} = "127.0.0.2"; # Dummy value.
    }

    return $yaml;
}

sub __read_file($) {
    my $filepath = shift;
    my $fh;
    unless (open $fh, '<', $filepath) {
        die sprintf "Couldn't read file '%s': %s\n", $filepath, $!;
    }
    my $data = do { local $/ = undef; <$fh> };
    close $fh;

    return $data;
}

1;
