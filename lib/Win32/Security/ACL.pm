#############################################################################
#
# Win32::Security::ACL - Win32 ACL manipulation
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

=head1 NAME

C<Win32::Security::ACL> - Win32 ACL manipulation

=head1 SYNOPSIS

	use Win32::Security::ACL;

	my $acl =  Win32::Security::ACL->new('FILE', $acl_string);
	my $acl2 = Win32::Security::ACL->new('FILE', @Aces);

=head1 DESCRIPTION

C<Win32::Security::ACL> and its subclasses provide an interface for interacting 
with Win32 ACLs (Access Control Lists).  The subclasses allow for variation in 
mask behavior (different privileges apply to files than apply to registry keys 
and so forth).  Note that it is still in development, so for now support for 
modification of ACLs is pretty much non-existent.

C<Win32::Security::ACL> uses the flyweight design pattern in conjunction with a 
persistent cache of demand-computed properties.  The result is that parsing of 
ACLs is only done for unique ACLs, and that the ACL objects themselves are very 
lightweight.

=head2 Installation instructions

This installs with MakeMaker as part of C<Win32::Security>.

To install via MakeMaker, it's the usual procedure - download from CPAN,
extract, type "perl Makefile.PL", "nmake" then "nmake install". Don't
do an "nmake test" because the I haven't written a test suite yet.

It depends upon C<Class::Prototyped> which should be installable via PPM or 
available on CPAN.  It also depends upon C<Win32::Security::ACE> , which is 
installed as part of C<Win32::Security>.

=head1 ARCHITECTURE

C<Win32::Security::ACL> uses some OO tricks to boost performance and clean up 
the design.  Here's a quick overview of the internal architecture, should you 
care!  It is possible to use C<Win32::Security::ACL> objects without 
understanding or reading any of this, because the public interface is designed 
to hide as much of the details as possible.  After all, that's the point of OO 
design.  If, however, you want to boost performance or to muck about in the 
internals, it's worth understanding how things were done.

=head2 Class Structure

C<Win32::Security::ACL> uses single inheritance similar to the C<_ObjectType> 
side of the multiple inheritance in C<Win32::Security::ACE>.  While not 
technically necessary, it was done in order to parallel the ACE design, and so
that the data caches could be maintained independently for each Object Type.

With that in mind, the class hierarchy looks like this:

=over 4

=item * C<Win32::Security::ACL>

=over 4

=item * C<Win32::Security::ACL::SE_FILE_OBJECT>

=back

=back


=head2 Flyweight Objects w/ Cached Demand-Computed Properties

On the typical computer systems, there are very few unique ACLs.  There may be 
hundred or thousands, but usually there are orders of magnitude fewer ACLs than 
there are objects to which they are applied.  In order to reduce the computation 
involved in analyzing them, the C<Win32::Security::ACL> caches all the 
information computed about each ACL in a central store (actually, multiple 
central stores - one for each Named Object type) based on the binary form 
(C<rawAcl>).  The object returned by a call to C<new> is a scalar reference to 
the anonymous hash for that C<rawAcl> in the central store.  Because it isn't a 
direct reference to the hash, it is possible to switch which hash the object 
points to on the fly.  This allows the C<Win32::Security::ACL> objects to be 
mutable while maintaining the immutability of the central store.  It also makes 
each individual C<Win32::Security::ACL> object incredibly lightweight, since it 
is only composed of a single blessed scalar.  To be safe, you may wish to 
C<clone> ACLs before modifying them, just to make sure that you aren't modifying 
someone else's ACL object.  The properties are computed as needed, but the 
results are cached in the central store.

For instance, once C<aces> has been computed for a given C<rawAcl>, 
it can be found from the object as C<< $$self->{aces} >>.  This 
should be used with care, although in some instances it is possible to reduce 
the number of method calls (should this be necessary for performance reasons) by 
making calls like so:

    $$acl->{aces} || [$acl->aces()];

That provides a fail-safe should the C<aces> value have not yet been computed 
while eliminating the method call if it has been.  Note that C<< $acl->aces() >> 
also derefences the array stored in the cache.

In order to defend against accidental manipulation, return values from the calls 
(although not from the direct access, obviously) are deep-copied one layer deep.  
That means that the results of C<< $acl->aces() >> can be safely manipulated 
without harming the ACL, but that the results of C<< $$acl->{aces} >> should be 
treated as read-only.

C<Win32::Security::ACL> objects returned are C<clone>d (using inlined code to 
reduce the performance hit).  The values returned from the C</^dbm.*/> calls are 
not cloned, however, so be careful there.

=cut

use Carp qw();
use Class::Prototyped;
use Win32::Security::ACE;

use strict;

BEGIN {
	Class::Prototyped->newPackage('Win32::Security::ACL');

	Win32::Security::ACL->reflect->addSlot(
		Win32::Security::ACE->reflect->getSlot('objectTypes'),
	);

	foreach my $objectType (@{Win32::Security::ACL->objectTypes()}) {
		Win32::Security::ACL->newPackage("Win32::Security::ACL::$objectType",
			objectType => $objectType,
			_rawAclCache => {},
		);
	}
}

=head1 Method Reference

=head2 C<new>
This creates a new C<Win32::Security::ACL> object.

The various calling forms are:

=over 4

=item * C<< Win32::Security::ACL->new($objectType, $rawAcl) >>

=item * C<< Win32::Security::ACL->new($objectType, @aces) >>

=item * C<< "Win32::Security::ACL::$objectType"->new($rawAcl) >>

=item * C<< "Win32::Security::ACL::$objectType"->new(@aces) >>

=item * C<< $acl_object->new($rawAcl) >>

=item * C<< $acl_object->new(@aces) >>

=back

Note that when using C<$objectType> in the package name, the value needs to be 
canonicalized (i.e. C<SE_FILE_OBJECT>, not the alias C<FILE>).  If the 
C<$objectType> has already been canonicalized, improved performance can be 
realized by making the call on the fully-qualified package name and thus 
avoiding the call to redo the canonicalization.  Aliases are permitted when 
passed as a parameter to the call.

To create a NULL ACL, pass an empty string (which will be interpreted as an 
empty C<rawAcl>).  Passing an empty list of ACEs creates an empty ACL, which is 
totally different from a NULL ACL.

If called on an C<Win32::Security::ACL> object, it creates a new ACL object of 
the same subclass comprised of the passed list of ACEs.

ACEs can be passed either as C<Win32::Security::ACE> objects or as anonymous 
arrays of parameters to be passed to
C<< Win32::Security::ACE::$objectType->New() >>.

=cut

Win32::Security::ACL->reflect->addSlot(
	new => sub {
		my $source = shift;

		my $class = ref($source) ? ref($source) : $source;

		$class =~ /^Win32::Security::ACL(?:::([^:]+))?$/ or Carp::croak("Win32::Security::ACL::new unable to parse classname '$class'.");
		my $objectType = $1;
		$objectType ||= Win32::Security::ACL->dbmObjectType()->explain_const(shift);

		my($rawAcl, $aces);

		if (scalar(@_) == 1 && !ref($_[0])) {
			$rawAcl = $_[0];
		} else {
			$aces = [map {ref($_) eq 'ARRAY' ? "Win32::Security::ACE::$objectType"->new(@$_) : $_} @_];
			$rawAcl = "Win32::Security::ACL::$objectType"->_buildRawAcl($aces);
		}

		my $_rawAclCache = "Win32::Security::ACL::$objectType"->_rawAclCache();

		my $thing = $_rawAclCache->{$rawAcl};
		unless ($thing) {
			$thing = $_rawAclCache->{$rawAcl} = {};
			$thing->{rawAcl} = $rawAcl;
			defined $aces and $thing->{aces} = [map {bless(\(my $o = $$_), ref($_))} @{$aces}];
		}

		my $self = \$thing;
		bless $self, "Win32::Security::ACL::$objectType";
		return $self;
	},
);


=head2 C<clone>

This creates a new C<Win32::Security::ACL> object that is identical in all 
forms, except for identity, to the original object.  Because of the flyweight 
design pattern, this is a very inexpensive operation.  However, should you wish 
to avoid the overhead of a method call, you can inline the code like so:

    bless(\(my $o = ${$obj}), ref($obj));

Basically, it derefences the scalar reference, assigns it to a temporary 
lexical, creates a reference to that, and then blesses it into the original 
package.  Nifty, eh?  Syntax stolen (with a few modifications) from 
C<Data::Dumper> output.

=cut

Win32::Security::ACL->reflect->addSlot(
	clone => sub {
		bless(\(my $o = ${$_[0]}), ref($_[0]));
	},
);


=head2 C<dbmObjectType>

Returns the C<Data::BitMask> object for interacting with Named Object Types.  
See C<Win32::Security::ACE->dbmObjectType()> for more explanation.

=cut

Win32::Security::ACL->reflect->addSlot(
	Win32::Security::ACE->reflect->getSlot('dbmObjectType'),
);


=head2 C<rawAcl>

Returns the binary string form of the ACL

=cut

Win32::Security::ACL->reflect->addSlot(
	rawAcl => sub {
		my $self = shift;
		my $thing = $$self;

		return $thing->{rawAcl};
	},
);


=head2 C<objectType>

Returns the type of object to which the ACE is or should be attached.

=cut

#Implementation during package instantiation


=head2 C<isNullAcl>

Tests for a NULL ACL.

=cut

Win32::Security::ACL->reflect->addSlot(
	isNullAcl => sub {
		my $self = shift;
		my $thing = $$self;

		return $thing->{rawAcl} eq "";
	},
);

Win32::Security::ACL->reflect->addSlot(
	_splitRawAcl => sub {
		my $self = shift;
		my $thing = $$self;

		$self->isNullAcl() and return;
		my $rawAcl = $self->rawAcl();

		my($aclRevision, $aclSize, $aceCount) = unpack("CxSSxx", substr($rawAcl, 0, 8));
		$rawAcl = substr($rawAcl, 8);

		$thing->{aces} = [];
		foreach my $i (0..$aceCount-1) {
			my($aceSize) = unpack("xxS", $rawAcl);
			my $rawAce = substr($rawAcl, 0, $aceSize);
			$rawAcl = substr($rawAcl, $aceSize);
			push( @{$thing->{aces}}, Win32::Security::ACE->new($self->objectType(), $rawAce) );
		}
	},
);

Win32::Security::ACL->reflect->addSlot(
	_buildRawAcl => sub {
		my $class = shift;
		my($aces) = @_;

		my $maxAceType = 0;
		foreach my $ace (@$aces) {
			UNIVERSAL::isa($ace, 'Win32::Security::ACE') or Carp::croak("Parameter '$ace' passed in anon array to Win32::Security::ACL::_buildRawAcl is not ACE!");
			my $tmp = $ace->rawAceType();
			$maxAceType = $tmp if $tmp > $maxAceType;
		}

		my $aclRevision = $maxAceType <= 3 ? 2 :
				($maxAceType <= 4 ? 3 :
					($maxAceType <= 8 ? 4 : -1));
		$aclRevision == -1 and Carp::croak("Unable to determine aclRevision value for MAX_ACE_TYPE of '$maxAceType' in Win32::Security::ACL::_buildRawAcl.");

		my $rawAcl = join('', map {$_->rawAce()} @$aces);
		$rawAcl = pack("CxSSxx", $aclRevision, length($rawAcl)+8, scalar(@$aces)).$rawAcl;
	},
);


=head2 C<aces>

Returns a list of C<Win32::Security::ACE> objects.  The ACEs are in the same
order as they are in the ACL.

It accepts an optional filter.  The filter should be an anonymous subroutine 
that looks for the ACE in C<$_> like C<grep> does.  The returned ACEs are 
C<clone>d to ensure that modifications to them do not modify the cached ACE 
values for that ACL.

=cut

Win32::Security::ACL->reflect->addSlot(
	aces => sub {
		my $self = shift;
		my $thing = $$self;
		my($filter) = @_;

		$self->isNullAcl() and return;
		exists $thing->{aces} or $self->_splitRawAcl();
		if (ref($filter) eq 'CODE') {
			return grep {&$filter} map {bless(\(my $o = $$_), ref($_))} @{$thing->{aces}};
		} else {
			return map {bless(\(my $o = $$_), ref($_))} @{$thing->{aces}};
		}
	},
);


=head2 C<aclRevision>

Returns the ACL Revision for the ACL.  In general, this should be C<2> 
(C<ACL_REVISION>) for normal ACLs and C<4> (C<ACL_REVISION_DS>) for ACLs that 
contain object-specific ACEs.

=cut

Win32::Security::ACL->reflect->addSlot(
	aclRevision => sub {
		my $self = shift;
		my $thing = $$self;

		$self->isNullAcl() and return;
		return (unpack("C", substr($self->rawAcl(), 0, 1)))[0];
	},
);


=head2 C<inheritable>

Accepts a type (either C<'OBJECT'> or C<'CONTAINER'>).  Returns the list of ACEs 
that would be inherited by a newly created child C<OBJECT> or C<CONTAINER> if 
the parent has this ACL.  It handle occluded permissions properly (for instance, 
if an container has an inherited permission granting READ access to Domain Users 
and someone adds an explicit and inherited FULL access to Domain Users to that 
container, child objects will not receive the inherited READ access because it 
is fully occluded by the also inherited FULL access).  As in C<aces>, the 
returned ACEs are C<clone>d for safety.

=cut

Win32::Security::ACL->reflect->addSlot(
	inheritable => sub {
		my $self = shift;
		my $thing = $$self;
		my($type) = @_;

		($type eq 'OBJECT' || $type eq 'CONTAINER') or Carp::croak("Need to pass OBJECT or CONTAINER to Win32::Security::ACL::inheritable.");
		my $call = "inheritable_$type";

		unless (exists $thing->{$call}) {
			my(@newAces);
			my $sidHash;

			foreach my $ace (map {$_->$call()} $self->aces()) {
				my $sid = $ace->sid();
				my $rawAccessMask = $ace->rawAccessMask();
				if (	($type eq 'CONTAINER' && $ace->aceFlags()->{INHERIT_ONLY_ACE}) ||
							!exists $sidHash->{$sid} ||
							!scalar(grep {($_ & $rawAccessMask) == $rawAccessMask} @{$sidHash->{$sid}})
						) {
					push(@{$sidHash->{$sid}}, $rawAccessMask);
					push(@newAces, $ace);
				}
			}

			$thing->{$call} = Win32::Security::ACL->new($self->objectType(), @newAces);
		}
		return bless(\(my $o = ${$thing->{$call}}), ref($thing->{$call}));
	},
);


=head2 C<compare_inherited>

Accepts C<$inheritable>, a C<Win32::Security::ACL> object, as a parameter.  The 
second object should ideally be generated by a call to C<inheritable>, and 
should be comprised solely of ACEs marked as C<INHERITED_ACE>.  The method 
compares the ACEs on the receiver marked as inherited with the ACEs for the 
passed object like so:

=over 4

=item *

Filters out ACEs not marked as C<INHERITED_ACE> from the list of those on the
receiver.

=item *

It starts at the beginning of the resulting lists and removes ACEs that match.  
This process stops at the first non-matching pair.

=item *

It starts at the end of the resulting lists and removes ACEs that match.  This 
process stops at the first non-matching pair.

=item *

It looks for a single 'CREATOR OWNER' ACE in the remainined entries of the 
passed object.  If it finds zero or more than one, then it skips to the next 
step.  It then looks for potentially matching entries in the remaining entries
for the receiver.  If it finds one and only one entry that matches on the
C<rawtype>, C<rawflags>, and C<rawmask>, it presumes that the entry in question
resulted from the 'CREATOR OWNER' ACE and removes both of them.  If it finds
no entry that matches, it presumes that 'CREATOR OWNER' was occluded by one of
the other ACEs and moves the 'CREATOR OWNER' entry from the passed object list.
If it finds multiple matching entries, it does nothing.

=back

It returns a list of anonymous arrays, the first consisting of an ACL and the 
second consisting of an C<$IMWX> value that can be interpreted as so:

=over 4

=item I

ACE is properly inherited from C<$inheritable>.

=item M

ACE should have been inherited from C<$inheritable>, but is missing!

=item W

ACE marked as C<INHERITED_ACE>, but there is no corresponding ACE to inherit in 
C<$inheritable>.

=item X

ACE explicitly assigned to object (i.e. C<INHERITED_ACE> is not set).

=back

If you pass a true value for the optional second parameter C<$flat>, the 
returned data will be flattened into a single list.  This is more difficult to 
interact with, but because the anonymous arrays don't have to be built, it is 
faster.  In both cases, the returned values are C<clone>d to ensure the safety
of the cached data.

=cut

Win32::Security::ACL->reflect->addSlot(
	compareInherited => sub {
		my $self = shift;
		my $thing = $$self;
		my($inhr, $flat) = @_;

		my $inhrThing = $inhr ? $$inhr : '';

		unless (exists $thing->{compareInherited}->{$inhrThing}) {
			my(@retval);

			my(@selfAces) = $self->aces();
			my(@inhrAces) = $inhr ? $inhr->aces() : ();

			push (@retval, map {[$_, ($_->aceFlags()->{INHERITED_ACE} ? 'I' : 'X')]} @selfAces);

			my(@selfIdxs) = (0..scalar(@selfAces)-1);
			my(@inhrIdxs) = (0..scalar(@inhrAces)-1);

			@selfIdxs = grep { $retval[$_]->[1] eq 'I' } @selfIdxs;

			my $missIdx = scalar(@selfIdxs) ? $selfIdxs[-1] : scalar(@retval);

			foreach my $idx (0, -1) {
				while (@selfIdxs) {
					if (${$selfAces[$selfIdxs[$idx]]} eq ${$inhrAces[$inhrIdxs[$idx]]}) {
						$missIdx = $selfIdxs[$idx];
						splice(@selfIdxs, $idx, 1);
						splice(@inhrIdxs, $idx, 1);
					} else {
						last;
					}
				}
			}

			my $iAceFlag = Win32::Security::ACE::_AceType::->dbmAceFlags()->build_mask('INHERITED_ACE');
			my(@inhrIdxsCo) = grep {$inhrAces[$_]->trustee() eq 'CREATOR OWNER' && $inhrAces[$_]->rawAceFlags() == $iAceFlag} @inhrIdxs;

			if (scalar(@inhrIdxsCo) == 1) {
				my $inhrAce = $inhrAces[$inhrIdxsCo[0]];

				my(@selfIdxsCo) = grep {
					$selfAces[$_]->rawAceType()  == $inhrAce->rawAceType() &&
					$selfAces[$_]->rawAceFlags() == $inhrAce->rawAceFlags() &&
					$selfAces[$_]->rawAccessMask()  == $inhrAce->rawAccessMask()
				} @selfIdxs;

				if (scalar(@selfIdxsCo) == 1) {
					$missIdx = $selfIdxsCo[0];
					@selfIdxs = grep {$_ ne $selfIdxsCo[0]} @selfIdxs;
					@inhrIdxs = grep {$_ ne $inhrIdxsCo[0]} @inhrIdxs;
				} elsif (scalar(@selfIdxsCo) == 0) {
					@inhrIdxs = grep {$_ ne $inhrIdxsCo[0]} @inhrIdxs;
				}
			}

			foreach my $i (@selfIdxs) {
				$retval[$i]->[1] = 'W';
				$missIdx = $i+1;
			}

			splice(@retval, $missIdx, 0, map {[$inhrAces[$_], 'M']} @inhrIdxs);

			$thing->{compareInherited}->{$inhrThing} = [map {@$_} @retval];
		}

		if ($flat) {
			my(@retval) = @{$thing->{compareInherited}->{$inhrThing}};
			foreach my $i (0..scalar(@retval)/2-1) {
				$retval[$i*2] = bless(\(my $o = ${$retval[$i*2]}), ref($retval[$i*2]));
			}
			return @retval;
		} else {
			my(@temp) = @{$thing->{compareInherited}->{$inhrThing}};
			my(@retval);
			foreach my $i (0..scalar(@temp)/2-1) {
				push(@retval, [bless(\(my $o = ${$temp[$i*2]}), ref($temp[$i*2])), $temp[$i*2+1]]);
			}
			return @retval;
		}
	},
);


=head2 C<addAces>

Adds ACEs to the C<Win32::Security::ACL> object.  ACEs may be passed as 
C<Win32::Security::ACE> objects, C<rawAce> strings, or anonymous arrays of 
parameters to be passed to C<< "Win32::Security::ACE::$objectType"->new() >>.  
The C<$objectType> value will be generated from the existing ACL.  If the 
existing ACEs in the ACL are not in the proper order, they will end up reordered 
as specified in http://support.microsoft.com/default.aspx?scid=kb;en-us;269159 .

=cut

Win32::Security::ACL->reflect->addSlot(
	addAces => sub {
		my $self = shift;
		my $thing = $$self;
		my(@aces) = @_;

		my $objectType = $self->objectType();

		foreach my $ace (@aces) {
			if (ref($ace) eq 'ARRAY') {
				$ace = "Win32::Security::ACE::$objectType"->new(@$ace);
			} elsif (!ref($ace)) {
				$ace = "Win32::Security::ACE::$objectType"->new($ace);
			}
		};

		push(@aces, $self->aces());

		my(%ace_blocks);

		foreach my $ace (@aces) {
			if ($ace->aceFlags->{INHERITED_ACE}) {
				push(@{$ace_blocks{INHERITED_ACE}}, $ace);
			} elsif ($ace->aceType() =~ /^ACCESS_(ALLOWED|DENIED)_(OBJECT_)?ACE_TYPE$/) {
				push(@{$ace_blocks{$ace->aceType()}}, $ace);
			} else {
				push(@{$ace_blocks{other}}, $ace);
			}
		}

		@aces = (
			@{$ace_blocks{ACCESS_DENIED_ACE_TYPE} || []},
			@{$ace_blocks{ACCESS_DENIED_OBJECT_ACE_TYPE} || []},
			@{$ace_blocks{ACCESS_ALLOWED_ACE_TYPE} || []},
			@{$ace_blocks{ACCESS_ALLOWED_OBJECT_ACE_TYPE} || []},
			@{$ace_blocks{other} || []},
			@{$ace_blocks{INHERITED_ACE} || []},
		);

		my $new_self = $self->new(@aces);
		$$self = $$new_self;
		return $self;
	},
);


=head2 C<deleteAces>

Deletes all ACEs matched by the passed filter from the ACL.  The filter should 
be an anonymous subroutine that looks for the ACEs in C<$_> like C<grep> does.

=cut

Win32::Security::ACL->reflect->addSlot(
	deleteAces => sub {
		my $self = shift;
		my $thing = $$self;
		my($filter) = @_;

		my $new_self = $self->new($self->aces(sub {!&$filter}));
		$$self = $$new_self;
		return $self;
	},
);


=head1 AUTHOR

Toby Ovod-Everett, tovod-everett@alascom.att.com

=cut

1;