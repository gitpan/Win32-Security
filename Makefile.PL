use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
	NAME  => 'Win32::Security',
	VERSION_FROM => 'lib/Win32/Security/NamedObject.pm', # finds $VERSION
	'PREREQ_PM' => {
		'Class::Prototyped' => '0.98',
		'Data::BitMask' => '0.13',
		'Win32::API' => undef,
	},
);

