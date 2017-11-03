use 5.022001;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'GKG::GKGtools',
    VERSION_FROM      => 'lib/GKG/GKGtools.pm', # finds $VERSION, requires EU::MM from perl >= 5.5
    PREREQ_PM         => {
	"Net::DNS::RR" => 0,
	"Net::DNS::Resolver" => 0,
	"Net::DNS::Packet" => 0,
         "JSON::XS" => 0,
         "HTTP::Request" => 0,
         "LWP::UserAgent" =>0,
	 "IPC::Open3" => 0,
	 "Getopt::Std" => 0,
	 "Fcntl" => 0,
    },
    ABSTRACT_FROM     => 'lib/GKG/GKGtools.pm', # retrieve abstract from module
    AUTHOR            => 'Eliot Lear <lear@ofcourseimright.com>',
    LICENSE           => 'bsd',
    EXE_FILES         => [ 'bin/gkgrm', 'bin/gkgls', 'bin/gkgadd', 'bin/ods-wrapper' ],
    #Value must be from legacy list of licenses here
    #http://search.cpan.org/perldoc?Module%3A%3ABuild%3A%3AAPI
);
