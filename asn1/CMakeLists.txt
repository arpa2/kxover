# Translate the required ASN.1 definitions to Erlang

cmake_minimum_required (VERSION 3.1 FATAL_ERROR)

set (KXOVER_LIBDIR ${CMAKE_BINARY_DIR}/erlang/kxover-${KXOVER_VERSION})

set (SPECNAMES RFC4120 RFC5280 KXOVER)


add_custom_command (OUTPUT kxover-libdir-asn1
	COMMAND cmake -E make_directory ${KXOVER_LIBDIR}/asn1)

#
# Targets deriving Erlang code from the Petri Nets perpetuum/*.pnml
#

set (OUTPUTFILES)
foreach (SPEC ${SPECNAMES})

	set (OUTPUTFILES ${OUTPUTFILES} ${KXOVER_LIBDIR}/asn1/${SPEC}.asn1)

	add_custom_command (OUTPUT ${KXOVER_LIBDIR}/asn1/${SPEC}.asn1
		COMMAND cmake -E copy ${CMAKE_CURRENT_SOURCE_DIR}/${SPEC}.asn1 ${KXOVER_LIBDIR}/asn1/${SPEC}.asn1
		DEPENDS kxover-libdir-asn1 ${CMAKE_CURRENT_SOURCE_DIR}/${SPEC}.asn1)

endforeach()

message (Made ASN.1 generate ${OUTPUTFILES})
add_custom_target (asn1-generated ALL
	DEPENDS ${OUTPUTFILES})


#ERLANG.MK-AUTOMATES# 
#ERLANG.MK-AUTOMATES# set (INNAMES)
#ERLANG.MK-AUTOMATES# set (OUTNAMES)
#ERLANG.MK-AUTOMATES# foreach (SPEC SPECNAMES)
#ERLANG.MK-AUTOMATES# 	set (INNAMES  ${INNAMES}  ${CMAKE_CURRENT_SOURCE_DIR}/${SPEC}.asn1)
#ERLANG.MK-AUTOMATES# 	set (OUTNAMES ${OUTNAMES} ${SPEC}.erl ${SPEC}.hrl ${SPEC}.beam)
#ERLANG.MK-AUTOMATES# endforeach()
#ERLANG.MK-AUTOMATES# 
#ERLANG.MK-AUTOMATES# add_custom_command (OUTPUT $OUTNAMES,
#ERLANG.MK-AUTOMATES# 	COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/compile.erl ${INNAMES}
#ERLANG.MK-AUTOMATES# 	DEPENDS ${INNAMES})

