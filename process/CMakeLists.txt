
#
# Erlang will be built using Erlang.mk, scripting for GNU make >= 4.0
#
# The result will then be harvested by CMake
#
# CMake invokes Erlang.mk as an ExternalProject
#

include (ExternalProject)

set (KXOVER_LIBDIR ${CMAKE_BINARY_DIR}/erlang/kxover-${KXOVER_VERSION})

add_custom_command (OUTPUT kxover-libdir
	COMMAND cmake -E make_directory ${KXOVER_LIBDIR}
	COMMAND cmake -E copy_directory
		${CMAKE_CURRENT_SOURCE_DIR}/src
		${KXOVER_LIBDIR}/src
	COMMAND cmake -E copy_directory
		${CMAKE_CURRENT_SOURCE_DIR}/include
		${KXOVER_LIBDIR}/include
	COMMAND cmake -E copy_directory
		${CMAKE_CURRENT_SOURCE_DIR}/ebin
		${KXOVER_LIBDIR}/ebin
	COMMAND cmake -E copy_directory
		${CMAKE_CURRENT_SOURCE_DIR}/doc
		${KXOVER_LIBDIR}/doc
	COMMAND cmake -E copy
		${CMAKE_CURRENT_SOURCE_DIR}/erlang.mk
		${KXOVER_LIBDIR}
	)

configure_file (${CMAKE_CURRENT_SOURCE_DIR}/Makefile.in
		${KXOVER_LIBDIR}/Makefile
		@ONLY)

add_custom_target (erlang-kxover-bootstrap
	DEPENDS kxover-libdir)

ExternalProject_Add (erlang_build
	DEPENDS erlang-kxover-bootstrap
	SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}
	# erlang_build_prepare
	# SOURCE_DIR .
	# PREFIX erlang
	STAMP_DIR stamp
	TMP_DIR tmp
	# BUILD_IN_SOURCE 1
	BUILD_COMMAND ${GNUMAKE} -C ${KXOVER_LIBDIR} all
	INSTALL_COMMAND ${GNUMAKE} -C ${KXOVER_LIBDIR} app)

add_test (erlang-common-tests ${GNUMAKE} -C ${KXOVER_LIBDIR} ct)
add_test (erlang-plt-dialyze  ${GNUMAKE} -C ${KXOVER_LIBDIR} plt dialyze)

#
# Targets deriving Erlang code from the Petri Nets perpetuum/*.pnml
#

add_custom_command (OUTPUT ${KXOVER_LIBDIR}/kxover_client.erl
	COMMAND perpetuum ${CMAKE_CURRENT_SOURCE_DIR}/perpetuum/kxover_client.pnml ${KXOVER_LIBDIR}
	DEPENDS erlang-kxover-bootstrap ${CMAKE_CURRENT_SOURCE_DIR}/perpetuum/kxover_client.pnml)

add_custom_command (OUTPUT ${KXOVER_LIBDIR}/kxover_server.erl
	COMMAND perpetuum ${CMAKE_CURRENT_SOURCE_DIR}/perpetuum/kxover_server.pnml ${KXOVER_LIBDIR}
	DEPENDS erlang-kxover-bootstrap ${CMAKE_CURRENT_SOURCE_DIR}/perpetuum/kxover_server.pnml)

#
# Targets to build the Erlang libraries
#

#add_custom_target (client
#	DEPENDS client.beam dns.beam kx.beam krbtgt.beam)

#add_custom_target (server
#	DEPENDS server.beam dns.beam kx.beam krbtgt.beam)

