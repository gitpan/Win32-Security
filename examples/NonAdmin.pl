#############################################################################
#
# NonAdmin.pl - lists files that don't have Administrators as the owner
#
# Author: Toby Ovod-Everett
#
#############################################################################
# Copyright 2003 Toby Ovod-Everett.  All rights reserved
#
# This program is free software; you can redistribute it and/or modify it
# under the same terms as Perl itself.
#
# For comments, questions, bugs or general interest, feel free to
# contact Toby Ovod-Everett at tovod-everett@alascom.att.com
#############################################################################

BEGIN { my $temp = (Win32::GetFullPathName($0))[0]; push(@INC, $temp) }

use Data::Dumper;
use File::DosGlob 'glob';
use Getopt::Long;
use Win32::Security::Recursor;

use strict;
use vars qw($counter $starttime);

$starttime = Win32::GetTickCount();

my $options = {};
GetOptions($options, qw(csv! recurse|s!));

$| = 1;
select((select(STDERR), $|=1)[0]);

@ARGV = map {/[*?]/ ? glob($_) : $_ } @ARGV;
@ARGV = (".") unless scalar(@ARGV);

my $recursor = Win32::Security::Recursor::FILE::PermDump->new($options,
		payload => sub {
			my $self = shift;
			my($node_info, $cont_info) = @_;

			$self->payload_count($self->payload_count()+1);

			my $name = exists $node_info->{name} ? $node_info->{name} : $self->node_name($node_info);
			my $iscontainer = exists $node_info->{iscontainer} ? $node_info->{iscontainer} : $self->node_iscontainer($node_info);
			my $node_namedobject = $node_info->{namedobject} || $self->node_namedobject($node_info);

			my $node_owner = $node_info->{owner} || $self->node_owner($node_info);
			$self->dump_line(name => $name, trustee => $node_owner, mask => 'OWNER', desc => $iscontainer ? 'DO' : 'FO') unless $node_owner eq "BUILTIN\\Administrators";
		},

		need_info => ['owner'],
);


$recursor->print_header();
foreach my $name (@ARGV) {
	$recursor->recurse($name);
}

if ($options->{performance}) {
	my $elapsed = Win32::GetTickCount()-$starttime;
	print STDERR sprintf("%i in %0.2f seconds (%i/s  %0.2f ms)\n", $recursor->{payload_count},
			($elapsed)/1000, $recursor->{payload_count}*1000/($elapsed || 1),
			$elapsed/($recursor->{payload_count} || 1)
		);
	print STDERR sprintf("%i unique ACEs, %i unique ACLs\n",
			scalar(keys %{$Win32::Security::ACE::rawace_cache->{SE_FILE_OBJECT}}),
			scalar(keys %{$Win32::Security::ACL::rawacl_cache->{SE_FILE_OBJECT}}) );
}
