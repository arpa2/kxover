#
# CMakeLists.txt for KXOVER
#

cmake_minimum_required (VERSION 3.2 FATAL_ERROR)
project ("KXOVER")

set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/cmake)

include (MacroEnsureOutOfSourceBuild)
include (MacroAddUninstallTarget)
include (MacroGitVersionInfo)
include (MacroCreateConfigFiles)
include (GNUInstallDirs)

macro_ensure_out_of_source_build("Do not build KXOVER in the source directory.")

#
# OPTIONS / BUILD SETTINGS
#

set (CMAKE_MACOSX_RPATH 0)

option (DEBUG
	"Switch on output and flags that aid developpers in debugging"
        OFF)

if (DEBUG)
	add_compile_options (-DDEBUG -ggdb3 -O0 -fstack-protector)
endif()

option (FAKE_TLS
	"Bypass TLS for now; use plain TCP and claim OK on any tests"
	OFF)

if (NOT FAKE_TLS)
	message (SEND_ERROR "Use the FAKE_TLS \"option\" -- we have no actual TLS support yet")
endif ()

option (ONLINE_TESTING
	"Testing may go online, using .DEMO.ARPA2.ORG demo realms with DNSSEC/DANE"
	ON)


#
# Dependencies
#

find_package (ARPA2CM QUIET NO_MODULE REQUIRED)
set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${ARPA2CM_MODULE_PATH})

find_package (Unbound REQUIRED)
find_package (Quick-DER REQUIRED)

# Constrain the acceptable KERBEROS system names
# to those that are supported in our source code
# set_property (CACHE Kerberos5_SYSTEM PROPERTY STRINGS mitkrb5 heimdal ad shishi)
set (MIT-krb5_CONFIG_MODULE kadm-client)
find_package (MIT-krb5 REQUIRED)
set_property (CACHE Kerberos5_SYSTEM PROPERTY STRINGS mitkrb5)

# find_program (GNUMAKE NAMES gmake make)

include_directories (Unbound_INCLUDE_DIRS Quick-DER_INCLUDE_DIRS)


#
# Version Information
#

get_version_from_git (KXOVER 0.0.0)


#
# Building
#

add_subdirectory (asn1)
include_directories (${KXOVER_INCDIR})

add_subdirectory (src)
add_subdirectory (test)

#KLUDGE#
# add_compile_options (-Dconst=)

# include_directories (include ${CMAKE_BINARY_DIR})

# add_executable (kxover_client
# 		kxover_client.c kxover_client.h kxover_server.h
# 		process/client.c process/common.c)

# add_executable (kxover_server
# 		kxover_server.c kxover_client.h kxover_server.h
# 		process/server.c process/common.c)


#
# TESTS
#

enable_testing ()


#
# INSTALLATION
#

add_uninstall_target ()


#
# PACKAGING
#

set (CPACK_PACKAGE_NAME "KXOVER")
set (CPACK_PACKAGE_VERSION ${KXOVER_VERSION})
set (CPACK_PACKAGE_VENDOR "ARPA2.net")
set (CPACK_PACKAGE_CONTACT "Rick van Rein <rick@openfortress.nl>")
# License information for packaging. This uses the SPDX license
# identifiers from https://spdx.org/licenses/
set (CPACK_FREEBSD_PACKAGE_LICENSE "BSD-2-Clause")

include (PackAllPossible)
include (CPack)

