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
        "Produce verbose about Petri net processing"
        OFF)


#
# Dependencies
#

# find_package (Quick-DER REQUIRED)
#TODO:DOESNT:INSTALL# find_package (Perpetuum REQUIRED)
#TODO:DOESNT:INSTALL# find_package (erlang-unbound REQUIRED)

find_program (GNUMAKE
	NAMES gmake make)


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
add_subdirectory (src)

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
