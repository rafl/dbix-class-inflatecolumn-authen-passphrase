use strict;
use warnings;

package DBIx::Class::InflateColumn::Authen::Passphrase;
# ABSTRACT: Inflate/deflate columns to Authen::Passphrase instances

use Authen::Passphrase;
use parent 'DBIx::Class';

=head1 SYNOPSIS

    __PACKAGE__->load_components(qw(InflateColumn::Authen::Passphrase));

    __PACKAGE__->add_columns(
        id => {
            data_type         => 'integer',
            is_auto_increment => 1,
        },
        passphrase_rfc2307 => {
            data_type          => 'text',
            inflate_passphrase => 'rfc2307',
        },
        passphrase_crypt => {
            data_type          => 'text',
            inflate_passphrase => 'crypt',
        },
    );

    __PACKAGE__->set_primary_key('id');


    # in application code
    $rs->create({ passphrase_rfc2307 => Authen::Passphrase::RejectAll->new });

    my $row = $rs->find({ id => $id });
    if ($row->passphrase_rfc2307->match($input)) { ...

=head1 DESCRIPTION

Provides inflation and deflation for Authen::Passphrase instances from and to
either RFC 2307 or crypt encoding.

To enable both inflating and deflating, C<inflate_passphrase> must be set to a
valid passhrase encoding. Currently the only supported encodings are C<rfc2307>
and C<crypt>. The specified encoding will be used both when storing
C<Authen::Passphrase> instances in columns, and when creating
C<Authen::Passphrase> instances from columns. See L<Authen::Passphrase> for
details on passphrase encodings.

=method register_column

Chains with the C<register_column> method in C<DBIx::Class::Row>, and sets up
passphrase columns appropriately. This would not normally be directly called by
end users.

=cut

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
