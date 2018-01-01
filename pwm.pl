#!@perl@

package aAuth;

use strict;
use warnings;

sub new {
    my ($class, $file) = @_;
    my $self = {
        file => $file
    };
    bless $self, $class;
    $self;
}

sub file {
    my ($self, $name) = @_;
    return $self->{'file'} unless $name;
    $self->{'file'} = $name;
    $self;
}

sub list {
    my $self = shift;
    open my $fh, '<', $self->file or return undef;
    my %hash;

    while (my $line = readline $fh) {
        chomp $line;
        my ($login, $hash, $gecos) = split ':', $line;
        next unless $hash;

        my ($dummy, $type, $salt, $sum) = split '\$', $hash;
        next unless $salt;
        next unless $sum;

        $hash{$login}{hash} = $hash;
        $hash{$login}{type} = $type;
        $hash{$login}{salt} = $salt;
        $hash{$login}{gecos} = $gecos;
        $hash{$login}{sum} = $sum;
    }
    \%hash;
}

sub profile {
    my ($self, $name) = @_;
    return undef unless $name;
    $self->list->{$name};
}

sub check {
    my ($self, $name, $password) = @_;
    return undef unless $name;
    my $profile = $self->list->{$name};
    return undef unless $profile;

    my $type = $profile->{type};
    my $salt = $profile->{salt};
    my $hash = $profile->{hash};

    my $new_hash;
    $new_hash = crypt($password, "\$$type\$$salt\$") if $type ne 'apr1';
    $new_hash = $self->apr($password, $salt) if $type eq 'apr1';
    return undef if $hash ne $new_hash;
    1;
}

sub update {
    my ($self, $name, %args) = @_;

    my $list = $self->list;
    return undef unless $list->{$name};

    my $profile = $list->{$name};
    my $hash = $profile->{hash};

    my $gecos = $args{gecos} || $profile->{gecos};

    my $new_password = $args{password};
    if ($new_password) {
        $list->{$name}->{hash} = $self->new_hash($new_password);
    }
    $self->write($list);
}

sub new_hash {
    my ($self, $password, $salt) = @_;
    return undef unless $password;

    my $type = '6';

    unless ($salt) {
        $salt = '';
        foreach (1..8) { $salt .= ('.', '/', 0..9, 'A'..'Z', 'a'..'z')[rand 64]; };
    }
    crypt($password, "\$$type\$$salt\$");
}


sub add {
    my ($self, $name, $password, $gecos) = @_;
    return undef unless $name;
    return undef unless $password;
    $gecos ||= '';

    my $list = $self->list;
    return undef if $list->{$name};

    my $hash = $self->new_hash($password);

    $list->{$name}->{hash} = $hash;
    $list->{$name}->{gecos} = $gecos;

    $self->write($list);
}

sub delete {
    my ($self, $name) = @_;
    return undef unless $name;

    my $list = $self->list;
    delete $list->{$name};
    $self->write($list);
}

sub write {
    my ($self, $list) = @_;

    $list = $self->list unless $list;

    my $file = $self->file;
    my $tmp = "$file.new";

    open my $fh, '>', $tmp or return undef;

    foreach my $name (sort keys %$list) {
        my $hash = $list->{$name}->{hash};
        my $gecos = $list->{$name}->{gecos};
        my $ret = print $fh "$name:$hash:$gecos\n";
        unless ($ret) {
            unlink $tmp;
            return undef;
        }
    }
    close $fh;
    rename $tmp, $file;
}

sub to64 {
    my $itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    my ($v, $n) = @_;
    my ($ret)  = '';
    while (--$n >= 0) {
        $ret .= substr($itoa64, $v & 0x3f, 1);
        $v >>= 6;
    }
    $ret;
}


sub apr {
    my($self, $password, $salt) = @_;
    return undef unless $password;
    return undef unless $salt;

    my $passwd;
    my $magic = '$apr1$';

    $salt =~ s/^\Q$magic//;
    $salt =~ s/^(.*)\$.*$/$1/;
    $salt = substr($salt, 0, 8);

    my $ctx = Digest::MD5->new;
    $ctx->add($password);
    $ctx->add($magic);
    $ctx->add($salt);

    my $final = Digest::MD5->new;
    $final->add($password);
    $final->add($salt);
    $final->add($password);

    $final = $final->digest;
    for (my $pl = length($password); $pl > 0; $pl -= 16) {
                $ctx->add(substr($final, 0, $pl > 16 ? 16 : $pl) );
    }
    for (my $i = length($password); $i; $i >>= 1) {
        if ($i & 1) {
            $ctx->add(pack('C', 0) );
        } else {
            $ctx->add(substr($password, 0, 1) );
        }
    }

    $final = $ctx->digest;

    for (my $i = 0; $i < 1000; $i++) {
        my ($ctx1) = Digest::MD5->new;
        if ($i & 1) {
            $ctx1->add($password);
        } else {
            $ctx1->add(substr($final, 0, 16) );
        }

        if ($i % 3) { $ctx1->add($salt); }
        if ($i % 7) { $ctx1->add($password); }
        if ($i & 1) { 
            $ctx1->add(substr($final, 0, 16) ); 
        } else {
            $ctx1->add($password);
        }

        $final = $ctx1->digest;
    }

    $passwd = '';
    $passwd .= to64(int(unpack('C', (substr($final, 0, 1))) << 16)
        | int(unpack('C', (substr($final, 6, 1) ) ) << 8)
        | int(unpack('C', (substr($final, 12, 1) ) ) ), 4);
    $passwd .= to64(int(unpack('C', (substr($final, 1, 1))) << 16)
        | int(unpack('C', (substr($final, 7, 1) ) ) << 8)
        | int(unpack('C', (substr($final, 13, 1) ) ) ), 4);
    $passwd .= to64(int(unpack('C', (substr($final, 2, 1))) << 16)
        | int(unpack('C', (substr($final, 8, 1) ) ) << 8)
        | int(unpack('C', (substr($final, 14, 1) ) ) ), 4);
    $passwd .= to64(int(unpack('C', (substr($final, 3, 1))) << 16)
        | int(unpack('C', (substr($final, 9, 1) ) ) << 8)
        | int(unpack('C', (substr($final, 15, 1) ) ) ), 4);
    $passwd .= to64(int(unpack('C', (substr($final, 4, 1))) << 16)
        | int(unpack('C', (substr($final, 10, 1) ) ) << 8)
        | int(unpack('C', (substr($final, 5, 1) ) ) ), 4);
    $passwd .= to64(int(unpack('C', substr($final, 11, 1))), 2);

    $magic . $salt . '$' . $passwd;
}


1;

use strict;
use warnings;
use Mojo::Util qw(dumper);

my $program = $0;

sub help {
    print "Usage:\n";
    print "  $program pwfile {add|del|pass} username\n";
}

my $file = $ARGV[0];
my $oper = $ARGV[1];
my $name = $ARGV[2];

do { help; exit 1} unless $file;
do { help; exit 1} unless $oper;
do { help; exit 1} unless $name;

$oper =~ s/^--//;

my $a = aAuth->new($file);

if ($oper =~ /^add/) {
    if ($a->profile($name)) {
        print "User already exist\n";
        exit 1;
    }
    print 'Password:'; 
    system "stty -echo";
    my $password1 = <STDIN>; 
    system "stty echo";
    chomp $password1;
    print "\nAgain:"; 
    system "stty -echo";
    my $password2 = <STDIN>;
    system "stty echo";
    chomp $password2;
    print "\n";

    if ($password1 ne $password2) {
        print "Password mismatch\n";
        exit 1;
    }
    my $res = $a->add($name, $password1);
    if ($res) {
        print "User was added\n";
        exit 0;
    } else {
        print "User has not added\n";
        exit 1;
    }

} elsif ($oper =~ /^del/) {

    unless ($a->profile($name)) {
        print "User not exist\n";
        exit 1;
    }

    my $res = $a->delete($name);
    if ($res) {
        print "User was deleted\n";
        exit 0;
    } else {
        print "User has not deleted\n";
        exit 1;
    }

} elsif ($oper =~ /^pass/) {
    print 'New password:'; my $password1 = <STDIN>; chomp $password1;
    print 'Again:'; my $password2 = <STDIN>; chomp $password2;

    if ($password1 ne $password2) {
        print "Password mismatch\n";
        exit 1;
    };
    my $res = $a->update($name, password => $password1);
    if ($res) {
        print "Password was updated\n";
        exit 0;
    } else {
        print "Password has not updated\n";
        exit 1;
    }
} else {
    help;
    exit 1;
}
#EOF
