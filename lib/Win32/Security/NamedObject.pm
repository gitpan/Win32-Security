#############################################################################
#
# Win32::Security::NamedObject - Security manipulation for named objects
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

C<Win32::Security::NamedObject> - Security manipulation for named objects

=head1 SYNOPSIS

	use Win32::Security::NamedObject;

	my $noFoo = Win32::Security::NamedObject->('FILE', "C:\\Foo\\foo.txt");
	my $dacl = $noFoo->dacl();
	print Data::Dumper->Dump([$dacl->aces()]);

=head1 DESCRIPTION

This module provide an object-oriented interface for manipulating security 
information on named objects (i.e. files, registry keys, etc.).  Note that, like 
the rest of C<Win32::Security>, it currently only provides support for files.  
It has been architected to eventually support all object types supported by the 
C<GetNamedSecurityInfo> Win32 API call.  Also, it currently only supports access 
to the DACL and Owner information - SACL access will come later.

=head2 Installation instructions

This installs with MakeMaker as part of C<Win32::Security>.

To install via MakeMaker, it's the usual procedure - download from CPAN,
extract, type "perl Makefile.PL", "nmake" then "nmake install". Don't
do an "nmake test" because the I haven't written a test suite yet.

It depends upon the other C<Win32::Security> modules.  The suite of 
C<Win32::Security> modules depends upon:

=over 4

=item C<Class::Prototyped> 0.98 or later

Support for prototype-based programming in Perl.  C<Win32::Security::ACE> uses 
this to programmatically generate large number of classes that use 
multiple-inheritance.  C<Win32::Security::ACL> and 
C<Win32::Security::NamedObject> use this to support programmatic generation of 
classes that interact with the C<Win32::Security::ACE> classes.  
C<Win32::Security::Recursor> uses this to allow for flexible behavior 
modification (since C<Win32::Security::Recursor> objects are really behavioral, 
not stateful).

=item C<Data::BitMask> 0.12 or later

Flexible support for manipulating masks and constants.

=item C<Win32::API>

Support for making Win32 API calls from Perl.  There is no C code anywhere in
C<Win32::Security>.  C<Win32::API> is why.

=back

All of the above modules should be available on CPAN, and also via PPM.

=head1 C<Win32::Security> MODULES

=head2 C<Win32::Security::SID>

C<Win32::Security::SID> provides a set of functions for doing SID manipulation 
(binary to text and vice-versa) as well as wrappers around 
C<Win32::LookupAccountName> and C<Win32::LookupAccountSID> that make them 
friendlier.

=head2 C<Win32::Security::Raw>

C<Win32::Security::Raw> provides a number of function wrappers around a number 
of Win32 API calls.  Each wrapper wraps around a single Win32 API call and 
provides rudimentary data structure marshalling and parsing.  This is the only 
module that uses C<Win32::API> to make API calls - all of the other modules 
make their API calls through the wrappers provided by this module.

=head2 C<Win32::Security::ACE>

C<Win32::Security::ACE> provides an object-oriented interface for parsing, 
creating, and manipulating Access Control Entries (ACEs).

=head2 C<Win32::Security::ACL>

C<Win32::Security::ACE> provides an object-oriented interface for manipulating 
Access Control Lists (ACLs).

=head2 C<Win32::Security::NamedObject>

C<Win32::Security::NamedObject> provides support for accessing and modifying the 
security information attached to Named Objects.

=head2 C<Win32::Security::Recursor>

C<Win32::Security::Recursor> provides support for recursing through trees of 
Named Objects and inspecting and/or modifying the security settings for those 
objects.


=head1 C<Win32::Security> SCRIPTS

Provided for your amusement and use are a few scripts that make use of the above 
modules.  These scripts were the raison d'etre for the modules, and so it seemed 
justifiable to ship them with it.  The scripts were located in the 
C<lib\\Win32\\Security> directory so that they will be automatically installed
as part of the package when deployed via PPM.  The scripts have documentation,
but here is a quick overview of them so that you don't overlook them.

=head2 C<PermDump.pl>

This utility dumps permissions on files.  It supports distinguishing between 
inherited and explicit permissions along with determining when there are 
problems with inherited permissions.  It has a number of options, and it's 
designed to output in either TDF or CSV format for easy parsing and viewing.

I would personally strongly recommend that all system administrators set up a 
nightly task to dump all the permissions on server volumes to a text file.  This 
makes it easy to recover should you make a mistake while doing permissions 
manipulation, and it also gives you a searchable file for looking for 
permissions without waiting for the script to dump permissions.  While the 
script is very fast and generally scans several hundred files per second, if you 
have a volume with hundreds of thousands of files, it can still take a while to 
run.

=head2 C<PermFix.pl>

This utility is designed to do one simple task: fix problems with inherited 
permissions.  This utility will be released shortly - I still need to do more
testing.  Contact me directly for a pre-release version if you want it.

=head2 C<PermChg.pl>

This utility is the counterpart to C<PermDump.pl>.  It allows you to change the 
permissions.  Unlike C<X?CACLS.EXE>, this utility properly understands and 
interacts with inherited permissions.  It supports two modes for specifying 
permissions.  The first allows you to specify permissions using the command line 
much like C<X?CACLS.EXE>.  The second allows you to pass the permissions in a 
text file using the same format as is outputted by C<PermDump.pl>.

Say you get a call from an executive insisting that Jane be given access to 
everything that John has access to.  The first step is to make Jane a member of 
all of the groups that John is in, but that doesn't address explicitly assigned 
permissions.  To deal with that, dump all the permissions on the volume using 
C<PermDump.pl>.  Open the file up in Excel and sort on the Trustee.  Copy the 
lines for John into another spreadsheet and replace the Trustee name with 
Jane's.  Then pass that into C<PermChg.pl> with the grant option and you're 
done!

This utility will be released shortly - I still need to do more development and
testing.  Contact me directly for a pre-release version if you want it.

=head1 ARCHITECTURE

C<Win32::Security::NamedObject> uses the same class architecture as 
C<Win32::Security::ACL>.  Unlike C<Win32::Security::ACE> and 
C<Win32::Security::ACL>, it B<doesn't> use the flyweight design pattern.  (For 
obvious reasons - you're unlikely to create multiple 
C<Win32::Security::NamedObject> objects for the same thing!)

=cut

use Carp qw();
use Class::Prototyped;
use Win32::Security::ACE;
use Win32::Security::ACL;
use Win32::Security::Raw;

use strict;

BEGIN {
	Class::Prototyped->newPackage('Win32::Security::NamedObject');

	Win32::Security::NamedObject->reflect->addSlots(
		Win32::Security::ACE->reflect->getSlot('objectTypes'),
	);

	foreach my $objectType (@{Win32::Security::NamedObject->objectTypes()}) {
		Win32::Security::NamedObject->newPackage("Win32::Security::NamedObject::$objectType",
			objectType => $objectType,
		);
	}
}

$Win32::Security::NamedObject::VERSION = '0.27';

=head1 Method Reference

=head2 C<new>
This creates a new C<Win32::Security::NamedObject> object.

The various calling forms are:

=over 4

=item * C<< Win32::Security::NamedObject->new($objectType, $objectName) >>

=item * C<< "Win32::Security::NamedObject::$objectType"->new($objectName) >>

=back

Note that when using C<$objectType> in the package name, the value needs to be 
canonicalized (i.e. C<SE_FILE_OBJECT>, not the shortcut C<FILE>).  If the 
C<$objectType> has already been canonicalized, improved performance can be 
realized by making the call on the fully-qualified package name and thus 
avoiding the call to redo the canonicalization.  Aliases are permitted when 
C<$objectName> is passed as a parameter.

The currently permitted objectName formats (text copied from 
http://msdn.microsoft.com/library/default.asp?url=/library/en-us/security/security/se_object_type.asp
) are:

=over 4

=item C<SE_FILE_OBJECT>

Indicates a file or directory. The name string that identifies a file or 
directory object can be:

=over 4

=item * 

A relative path, such as C<"abc.dat"> or C<"..\\abc.dat">

=item *

An absolute path, such as C<"\\abc.dat">, C<"c:\\dir1\\abc.dat">, or 
C<"g:\\remote_dir\\abc.dat">

=item *

A UNC name, such as C<"\\\\computer_name\\share_name\\abc.dat">

=item *

A local file system root, such as C<"\\\\\\\\.\\\\c:">. Security set on a file 
system root does not persist when the system is restarted

=back

=item C<SE_REGISTRY_KEY>

Indicates a registry key. A registry key object can be in the local registry, 
such as C<"CLASSES_ROOT\\some_path">; or in a remote registry, such as 
C<"\\\\computer_name\\CLASSES_ROOT\\some_path">. The names of registry keys must 
use the following literal strings to identify the predefined registry keys: 
C<"CLASSES_ROOT">, C<"CURRENT_USER">, C<"MACHINE">, and C<"USERS">.

In addition, the following literal strings will be mapped to the legal literals:

=over 4

=item *

C<HKEY_CLASSES_ROOT> -> C<CLASSES_ROOT>

=item *

C<HKEY_CURRENT_USER> -> C<CURRENT_USER>

=item *

C<HKEY_LOCAL_MACHINE> -> C<MACHINE>

=item *

C<HKEY_USERS> -> C<USERS>

=back

=cut

Win32::Security::NamedObject->reflect->addSlot(
	new => sub {
		my $class = shift;

		$class =~ /^Win32::Security::NamedObject(?:::([^:]+))?$/ or Carp::croak("Win32::Security::NamedObject::new unable to parse classname '$class'.");
		my $objectType = $1;

		unless ($objectType) {
			$objectType ||= Win32::Security::NamedObject->dbmObjectType()->explain_const(shift);
			return "Win32::Security::NamedObject::$objectType"->new(@_);
		}

		my $objectName = shift;

		my $self = {
			objectName => $objectName,
			objectType => $objectType,
		};

		bless $self, $class;

		return $self;
	},
);

Win32::Security::NamedObject::SE_REGISTRY_KEY->reflect->addSlot(
	new => sub {
		my $class = shift;

		my $objectName = shift;

		my $mappings = {
			HKEY_CLASSES_ROOT => 'CLASSES_ROOT',
			HKEY_CURRENT_USER => 'CURRENT_USER',
			HKEY_LOCAL_MACHINE => 'MACHINE',
			HKEY_USERS => 'USERS',
		};

		if ($objectName =~ /^([^\\]+)(\\[^\\].*)?$/) {
			my($key, $rest) = ($1, $2);
			$key = $mappings->{$key} || $key;
			$objectName = $key.$rest;
		} elsif ($objectName =~ /^(\\\\[^\\]+\\)([^\\]+)(\\[^\\].*)?$/) {
			my($first, $key, $rest) = ($1, $2);
			$key = $mappings->{$key} || $key;
			$objectName = $first.$key.$rest;
		}

		my $self = {
			objectName => $objectName,
			objectType => 'SE_REGISTRY_KEY',
		};

		bless $self, $class;

		return $self;
	},
);

=head2 C<dbmObjectType>

Returns the C<Data::BitMask> object for interacting with Object Types

See C<Win32::Security::ACE->dbmObjectType()> for more explanation.

=cut

Win32::Security::NamedObject->reflect->addSlot(
	Win32::Security::ACE->reflect->getSlot('dbmObjectType'),
);


=head2 C<objectType>

Returns the type of object to which the ACE is or should be attached.

=cut

#implemented during package instantiation


=head2 C<objectName>

Returns the name of the object.

=cut

Win32::Security::NamedObject->reflect->addSlot(
	objectName => sub {
		my $self = shift;
		
		return $self->{objectName};
	},
);


=head2 C<dacl>

Gets or sets the DACL for the object.  If no parameters are passed, it reads the 
DACL for the object and returns a C<Win32::Security::ACL> class object.  To set 
the DACL, pass the desired C<Win32::Security::ACL> for the object and an 
optional C<SECURITY_INFORMATION> mask for specifying the bits 
C<UNPROTECTED_DACL_SECURITY_INFORMATION> or 
C<PROTECTED_DACL_SECURITY_INFORMATION>.  If the 
C<UNPROTECTED_DACL_SECURITY_INFORMATION> is set, then permissions are inherited.  
If C<PROTECTED_DACL_SECURITY_INFORMATION> is set, then permissions are NOT 
inherited (i.e. inheritance is blocked).  If neither is set, then the existing 
setting is maintained.

Be forewarned that when setting the DACL, under Windows 2000 and more recent 
OSes, the call to C<SetNamedSecurityInfo> results in the automatic propagation 
of inheritable ACEs to existing child object (see 
http://msdn.microsoft.com/library/default.asp?url=/library/en-us/security/security/setnamedsecurityinfo.asp
for more information).  This does B<not> happen under Windows NT, and if you 
need propagation of inheritable permissions under Windows NT, you need to write 
your own code to implement that.  Under OSes that support automatic propagation, 
the call to set a DACL can take a very long time to return!  Finally, any errors 
in the inherited DACLs buried in the tree will be automatically fixed by this
call.

When setting the DACL under Windows 2000 and more recent OSes, if 
C<UNPROTECTED_DACL_SECURITY_INFORMATION> is specified, or if the 
C<SECURITY_INFORMATION> mask is unspecified and the object is currently 
inheriting permissions, then any ACEs in the passed DACL that have the 
C<INHERITED_ACE> bit set in C<aceFlags> are automatically ignored.  The OS will 
automatically propagate the inheritable ACEs and will only explicitly set those 
ACEs in the passed DACL that do not have the C<INHERITED_ACE> bit set in 
C<aceFlags>.

If C<PROTECTED_DACL_SECURITY_INFORMATION> is specified, or if the 
C<SECURITY_INFORMATION> mask is unspeciied and the object is currently blocking 
inherited permissions, than the C<INHERITED_ACE> bit in C<aceFlags> for all ACEs 
in the passed DACL is automatically cleared.  That is to say, all passed ACEs 
are treated as explicit, independent of the C<INHERITED_ACE> bit in C<aceFlags>.

=cut

Win32::Security::NamedObject->reflect->addSlot(
	dacl => sub {
		my $self = shift;

		unless (scalar(@_)) {
			unless (exists $self->{dacl}) {
				my $objectType = $self->{objectType} || $self->objectType();

				eval {
					my($psidOwner, $psidGroup, $pDacl, $pSacl, $pSecurityDescriptor) =
							Win32::Security::Raw::GetNamedSecurityInfo($self->{objectName} || $self->objectName(), $objectType, 'DACL_SECURITY_INFORMATION');
					$self->{control} = (Win32::Security::Raw::GetSecurityDescriptorControl($pSecurityDescriptor))[0];

					if ($pDacl) {
						my($AceCount, $AclBytesInUse, $AclBytesFree) = Win32::Security::Raw::GetAclInformation($pDacl, 'AclSizeInformation');
						$self->{dacl} = "Win32::Security::ACL::$objectType"->new(Win32::Security::Raw::CopyMemory_Read($pDacl, $AclBytesInUse));
					} else {
						$self->{dacl} = "Win32::Security::ACL::$objectType"->new(undef);
					}

					Win32::Security::Raw::LocalFree($pSecurityDescriptor);
				};
				$@ and $self->_cleansedCroak($@);
			}
			return bless(\(my $o = ${$self->{dacl}}), ref($self->{dacl}));

		} else {
			my($dacl, $SecurityInfo) = @_;

			my $objectType = $self->{objectType} || $self->objectType();

			eval {
				delete $self->{dacl};
				$SecurityInfo = &Win32::Security::SECURITY_INFORMATION->build_mask($SecurityInfo);
				$SecurityInfo = &Win32::Security::SECURITY_INFORMATION->break_mask($SecurityInfo);
				$SecurityInfo->{DACL_SECURITY_INFORMATION} = 1;
				$SecurityInfo = &Win32::Security::SECURITY_INFORMATION->build_mask($SecurityInfo);
				Win32::Security::Raw::SetNamedSecurityInfo($self->objectName(), $objectType, $SecurityInfo,
						undef, undef, $dacl->rawAcl(), undef);
			};
			$@ and $self->_cleansedCroak($@);

		}
	},
);


=head2 C<ownerTrustee>

Gets or sets the Trustee for the Owner of the object.  If no parameters are 
passed, it reads the Owner for the object and returns a Trustee name.  To set 
the Owner, pass the desired Trustee.  It calls C<ownerSid>, so see that method 
for information on C<SeRestorePrivilege>.

=cut

Win32::Security::NamedObject->reflect->addSlot(
	ownerTrustee => sub {
		my $self = shift;

		unless (scalar(@_)) {
			unless ($self->{ownerTrustee}) {
				my $Sid = $self->ownerSid();
				$self->{ownerTrustee} = eval { Win32::Security::SID::ConvertSidToName($Sid) };
				$@ and $self->_cleansedCroak($@);
			}
			return $self->{ownerTrustee};
		} else {
			my($Trustee) = @_;
			my $Sid = eval { Win32::Security::SID::ConvertNameToSid($Trustee) };
			$@ and $self->_cleansedCroak($@);
			$self->ownerSid($Sid);
		}
	},
);


=head2 C<ownerSid>

Gets or sets the binary SID for the Owner of the object.  If no parameters are 
passed, it reads the Owner for the object and returns a binary SID.  To set the 
Owner, pass the desired binary SID.  The first time this is called in set mode, 
it will attempt to enable the C<SeRestorePrivilege>, which permits setting the 
Owner of an object to anyone.

=cut

{
my $ser_attempted;

Win32::Security::NamedObject->reflect->addSlot(
	ownerSid => sub {
		my $self = shift;

		my $objectType = $self->objectType();

		unless (scalar(@_)) {
			unless (exists $self->{owner}) {
				eval {
					my($ppsidOwner, $ppsidGroup, $ppDacl, $ppSacl, $ppSecurityDescriptor) =
							Win32::Security::Raw::GetNamedSecurityInfo($self->{objectName}, $objectType, 'OWNER_SECURITY_INFORMATION');
					my $sidLength = Win32::Security::Raw::GetLengthSid($ppsidOwner);
					my $Sid = Win32::Security::Raw::CopyMemory_Read($ppsidOwner, $sidLength);
					$self->{ownerSid} = $Sid;
					Win32::Security::Raw::LocalFree($ppSecurityDescriptor);
				};
				$@ and $self->_cleansedCroak($@);
			}
			return $self->{ownerSid};
		} else {
			my($Sid) = @_;

			unless ($ser_attempted) {
				eval {
					my $th = Win32::Security::Raw::OpenProcessToken(Win32::Security::Raw::GetCurrentProcess(), "TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY");
					my $luid = Win32::Security::Raw::LookupPrivilegeValue(undef, 'SeRestorePrivilege');
					my $ps = Win32::Security::Raw::AdjustTokenPrivileges($th, 0, [ [$luid, 'SE_PRIVILEGE_USED_FOR_ACCESS'] ]);
					$ps->[0]->[0] = $luid;
					$ps->[0]->[1]->{SE_PRIVILEGE_ENABLED} = 1;
					Win32::Security::Raw::AdjustTokenPrivileges($th, 0, $ps);
				};
				$ser_attempted = 1;
			}

			eval {
				delete $self->{owner};
				delete $self->{ownerSid};

				Win32::Security::Raw::SetNamedSecurityInfo($self->{objectName}, $objectType,
						&Win32::Security::SECURITY_INFORMATION->build_mask('OWNER_SECURITY_INFORMATION'),
						$Sid, undef, undef, undef);

				$self->{ownerSid} = $Sid;
			};
			$@ and $self->_cleansedCroak($@);
		}
	},
);
}


=head2 C<control>

Returns the C<Data::BitMask::break_mask> form of the Security Descript Control 
(i.e. a hash containing all matching constants for the control mask of the SD).

=cut

Win32::Security::NamedObject->reflect->addSlot(
	control => sub {
		my $self = shift;

		$self->{dacl} || $self->dacl();
		return {%{$self->{control}}};
	},
);


=head2 C<fixDacl>

Fixes the inherited ACEs in the DACL.  See the caveats concerning setting DACLS 
using C<dacl> for further information.

=cut

Win32::Security::NamedObject->reflect->addSlot(
	fixDacl => sub {
		my $self = shift;

		my $dacl = $self->dacl();
		$self->dacl($dacl);
	},
);


#This strips trailing carriage returns and the like from the error message so 
#that line numbers get appended

Win32::Security::NamedObject->reflect->addSlot(
	_cleansedCroak => sub {
		my $self = shift;

		$_[0] =~ s/[\r\n]+$//;
		goto &Carp::croak;
	},
);

=head1 AUTHOR

Toby Ovod-Everett, tovod-everett@alascom.att.com

=cut

1;