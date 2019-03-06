# Finds the MIT-krb5 libraries as instances of MIT-krb5_xxx
#
#  MIT-krb5_FOUND          - Set to "mitkrb5" if MIT krb5 is found
#  MIT-krb5_VERSION        - Version of the library found
#  MIT-krb5_INCLUDE_DIRS   - Directories to include to get MIT krb5 headers
#  MIT-krb5_LIBRARIES      - Libraries to link against for MIT krb5
#  MIT-krb5_DEFINITIONS    - Definitions to add to the compiler
#
# Since other Kerberos systems exist, notably Heimdal and possibly
# one day Shishi, is some continued work to put the values into
# more general variables:
#
#  Kerberos5_SYSTEM        - Would be set to "mitkrb5" for us
#  Kerberos5_FOUND         - Copied from MIT-krb5_FOUND for "mitkrb5"
#  Kerberos5_VERSION       - Copied from MIT-krb5_VERSION
#  Kerberos5_INCLUDE_DIRS  - Copied from MIT-krb5_INCLUDE_DIRS
#  Kerberos5_LIBRARIES     - Copied from MIT-krb5_LIBRARIES
#  Kerberos5_DEFINITIONS   - Copied from MIT-krb5_DEFINITIONS
#
# The logic of Kerberos5_SYSTEM is "pluggable", in that it will be
# set (with cache) to "mitkrb5" if it is not yet set.  If it has a
# value but not "mitkrb5", none of the Kerberos5_xxx is changed.
#
include(FeatureSummary)

set_package_properties(MIT-krb5 PROPERTIES
	DESCRIPTION "Find MIT-krb5 development goodies"
	URL "http://web.mit.edu/kerberos/krb5-latest/doc/appdev/index.html"
)

set (MIT-krb5_SYSTEM "mitkrb5")

if ("${MIT-krb5_FOUND}" STREQUAL "${MIT-krb5_SYSTEM}")
	set (MIT-krb5_QUIETLY TRUE)
endif()

find_program (MIT-krb5_CONFIG
	NAMES "krb5-config.mit"
	)#DOC "Configuration program for MIT-krb5 (validity depends on MIT-krb5_FOUND)")

exec_program (${MIT-krb5_CONFIG}
		ARGS --vendor
		OUTPUT_VARIABLE MIT-krb5_VENDOR)

if ("${MIT-krb5_VENDOR}" STREQUAL "Massachusetts Institute of Technology")
	set (MIT-krb5_FOUND TRUE)
endif ()

exec_program (${MIT-krb5_CONFIG}
		ARGS --version
		OUTPUT_VARIABLE MIT-krb5_VERSION)

exec_program (${MIT-krb5_CONFIG}
		ARGS --cflags
		OUTPUT_VARIABLE MIT-krb5_DEFINITIONS)

exec_program (${MIT-krb5_CONFIG}
		ARGS --libs --deps
		OUTPUT_VARIABLE MIT-krb5_LIBRARIES)

if (Kerberos5_SYSTEM)
	if (NOT "${Kerberos5_SYSTEM}" STREQUAL "${MIT-krb5_SYSTEM}")
		unset (MIT-krb5_FOUND)
	endif ()
endif ()

if (MIT-krb5_FOUND)
	if (NOT MIT-krb5_QUIETLY)
		message (STATUS "Found package MIT-krb5 ${MIT-krb5_VERSION}")
		message (STATUS "Compiler definitions for MIT-krb5 are \"${MIT-krb5_DEFINITIONS}\"")
		message (STATUS "Libraries for MIT-krb5 linking are \"${MIT-krb5_LIBRARIES}\"")
	endif ()
else()
	if (MIT-krb5_FIND_REQUIRED)
		message (FATAL_ERROR "Could not find REQUIRED package MIT-krb5")
	else()
		message (STATUS "Optional package MIT-krb5 was not found")
	endif()
endif()


# CMakeFile Constraint: set_property (CACHE Kerberos5_SYSTEM PROPERTY STRINGS mitkrb5 heimdal ad shishi)
if (NOT Kerberos5_SYSTEM)
	set (Kerberos5_SYSTEM
		${MIT-krb5_SYSTEM}
		CACHE STRING "The selected Kerberos implementation")
endif()

if ("${Kerberos5_SYSTEM}" STREQUAL "${MIT-krb5_SYSTEM}")
	set (Kerberos5_FOUND "${MIT-krb5_FOUND}")
	set (Kerberos5_VERSION "${MIT-krb5_VERSION}")
	set (Kerberos5_INCLUDE_DIRS "${MIT-krb5_INCLUDE_DIRS}")
	set (Kerberos5_LIBRARIES "${MIT-krb5_LIBRARIES}")
	set (Kerberos5_DEFINITIONS "${MIT-krb5_DEFINITIONS}")
	if (NOT MIT-krb5-QUIETLY)
		message (STATUS "Defined Kerberos5_SYSTEM as \"${MIT-krb5_SYSTEM}\"")
	endif()
endif ()

