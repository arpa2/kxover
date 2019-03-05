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

macro_ensure_out_of_source_build("Do not build KXOVER in the source directory.")

set (CMAKE_MACOSX_RPATH 0)

option (DEBUG
	"Switch on output and flags that aid developpers in debugging"
        OFF)

if (DEBUG)
	add_compile_options (-DDEBUG -ggdb3 -O0)
endif()

option (FAKE_TLS
	"Bypass TLS for now; use plain TCP and claim OK on any tests"
	OFF)


#
# Dependencies
#

find_package (ARPA2CM QUIET NO_MODULE REQUIRED)
set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${ARPA2CM_MODULE_PATH})

find_package (Unbound REQUIRED)
find_package (Quick-DER REQUIRED)

# find_program (GNUMAKE NAMES gmake make)

include_directories (Unbound_INCLUDE_DIRS Quick-DER_INCLUDE_DIRS)

#
# OPTIONS / BUILD SETTINGS
#

set (PERPETUUM_COMPILER_PATH "perpetuum"
	CACHE PATH "Command or path for the Perpetuum Compiler")


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
