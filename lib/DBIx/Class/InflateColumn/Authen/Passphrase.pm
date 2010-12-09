use strict;
use warnings;

package DBIx::Class::InflateColumn::Authen::Passphrase;

use Authen::Passphrase;
use parent 'DBIx::Class';

sub register_column {
    my ($self, $column, $info, @rest) = @_;

    $self->next::method($column, $info, @rest);
    return unless my $encoding = $info->{inflate_passphrase};

    $self->throw_exception(q['rfc2307' and 'crypt' are the only supported types of passphrase columns])
        unless $encoding eq 'rfc2307' || $encoding eq 'crypt';

    $self->inflate_column(
        $column => {
            inflate => sub { Authen::Passphrase->${\"from_${encoding}"}(shift) },
            deflate => sub { shift->${\"as_${encoding}"} },
        },
    );
}

1;
