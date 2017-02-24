#
# CMakeLists.txt for KXOVER
#

cmake_minimum_required (VERSION 3.1 FATAL_ERROR)
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

find_package (Quick-DER REQUIRED)
find_package (Perpetuum REQUIRED)


#
# Version Information
#

get_version_from_git (KXOVER 0.0.0)


#
# Building
#

#KLUDGE#
add_compile_options (-Dconst=)

include_directories (include ${CMAKE_BINARY_DIR})

add_custom_command (OUTPUT kxover_client.c kxover_client.h
		COMMAND perpetuum-codegen
			${CMAKE_SOURCE_DIR}/process/petrinet/kxover_client.pnml
			${CMAKE_BINARY_DIR})

add_custom_command (OUTPUT kxover_server.c kxover_server.h
		COMMAND perpetuum-codegen
			${CMAKE_SOURCE_DIR}/process/petrinet/kxover_server.pnml
			${CMAKE_BINARY_DIR})

add_executable (kxover_client
		kxover_client.c
		kxover_client.h kxover_server.h
		process/client.c process/common.c)

add_executable (kxover_server
		kxover_server.c
		kxover_client.h kxover_server.h
		process/server.c process/common.c)

# add_custom_command (TARGET kxover_client
# 		PRE_BUILD
# 		COMMAND perpetuum-codegen
# 			${CMAKE_SOURCE_DIR}/process/petrinet/kxover_client.pnml
# 			${CMAKE_BINARY_DIR})

# add_custom_command (TARGET kxover_client
# 		PRE_BUILD
# 		COMMAND perpetuum-codegen
# 			${CMAKE_SOURCE_DIR}/process/petrinet/kxover_client.pnml
# 			${CMAKE_BINARY_DIR})

add_custom_command (TARGET kxover_server
		PRE_BUILD
		COMMAND perpetuum-codegen
			${CMAKE_SOURCE_DIR}/process/petrinet/kxover_server.pnml
			${CMAKE_BINARY_DIR})

add_custom_command (TARGET kxover_client
		PRE_BUILD
		COMMAND perpetuum-codegen
			${CMAKE_SOURCE_DIR}/process/petrinet/kxover_client.pnml
			${CMAKE_BINARY_DIR})

add_custom_command (TARGET kxover_server
		PRE_BUILD
		COMMAND perpetuum-codegen
			${CMAKE_SOURCE_DIR}/process/petrinet/kxover_server.pnml
			${CMAKE_BINARY_DIR})

add_custom_command (TARGET kxover_client
		PRE_BUILD
		COMMAND perpetuum-codegen
			${CMAKE_SOURCE_DIR}/process/petrinet/kxover_client.pnml
			${CMAKE_BINARY_DIR})

add_custom_command (TARGET kxover_server
		PRE_BUILD
		COMMAND perpetuum-codegen
			${CMAKE_SOURCE_DIR}/process/petrinet/kxover_server.pnml
			${CMAKE_BINARY_DIR})

add_custom_command (TARGET kxover_server
		PRE_BUILD
		COMMAND perpetuum-codegen
			${CMAKE_SOURCE_DIR}/process/petrinet/kxover_server.pnml
			${CMAKE_BINARY_DIR})


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
