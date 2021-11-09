package Edge::ClientAPI::Feed::VSS_FPS;
use common::sense;
use Try::Tiny;
use YAML::Tiny;
use Data::Dumper;
use Safe::Isa;
use Edge::ClientAPI::E;

sub new {
    my ($class) = @_;
    return bless +[], $class;
}

sub add {
    my ($self, $vs_ip, $vs_port, $fps, $tlss) = @_;

    # It is allowed to duplicate $vs_ip and $vs_port.
    push @$self, { vs   => { ip => $vs_ip, port => $vs_port },
                   tlss => $tlss,
                   fps  => $fps };
    ()
}

sub has_vs {
    my ($self, $ip, $port) = @_;
    for my $el (@$self) {
        if ($ip eq $el->{vs}{ip} && $port == $el->{vs}{port}) {
            return 1;
        }
    }
    return 0;
}

sub get_fps_by_vs {
    my ($self, $ip, $port) = @_;
    for my $el (@$self) {
        if ($ip eq $el->{vs}{ip} && $port == $el->{vs}{port}) {
            return $el->{fps};
        }
    }
    return undef;
}

sub get_tlss_by_vs {
    my ($self, $ip, $port) = @_;
    for my $el (@$self) {
        if ($ip eq $el->{vs}{ip} && $port == $el->{vs}{port}) {
            return $el->{tlss}; # Can be undefined.
        }
    }
    return undef;
}

sub enum {
    my ($self, $cb) = @_;
    die "No callback" unless ref $cb eq 'CODE';
    for my $el (@$self) {
        $cb->($el);
    }
    ()
}

sub get_all_uniq_fps_names {
    my $self = shift;

    my %all;
    for my $el (@$self) {
        my $fps = $el->{fps};
        next unless $fps;
        my $names = $fps->get_fps_names;
        next unless $names;
        # Merge names
        for my $name (sort keys %$names) {
            $all{$name}++;
        }
    }

    return %all ? \%all : undef;
}

sub get_all_uniq_cert_names {
    my $self = shift;

    my %all;
    for my $el (@$self) {
        my $tlss = $el->{tlss};
        next unless $tlss;
        my $names = $tlss->get_tlss_names;
        next unless $names;
        # Merge names
        for my $name (sort keys %$names) {
            $all{$name}++;
        }
    }

    return %all ? \%all : undef;
}

1;
