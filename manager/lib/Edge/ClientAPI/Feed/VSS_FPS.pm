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
    my ($self, $vs_ip, $vs_port, $fps) = @_;

    push @$self, { vs  => { ip => $vs_ip, port => $vs_port },
                   fps => $fps };
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

sub enum {
    my ($self, $cb) = @_;
    die "No callback" unless ref $cb eq 'CODE';
    for my $el (@$self) {
        $cb->($el);
    }
    ()
}

1;
