# Translate the required ASN.1 definitions to Erlang

cmake_minimum_required (VERSION 3.1 FATAL_ERROR)

#ERLANG.MK# set (KXOVER_LIBDIR ${CMAKE_BINARY_DIR}/erlang/kxover-${KXOVER_VERSION})
# set (KXOVER_LIBDIR ${CMAKE_BINARY_DIR})
set (KXOVER_DOCDIR ${CMAKE_BINARY_DIR}/doc)
set (KXOVER_INCDIR ${CMAKE_BINARY_DIR}/include)
set (KXOVER_INCDIR ${CMAKE_BINARY_DIR}/include PARENT_SCOPE)
set (QUICKDER_INCDIR ${KXOVER_INCDIR}/quick-der)

set (SPECNAMES rfc3280 rfc4120 rfc4556 rfc5280 kxover kxover-autzdata kxover-priorkey-entropy)


# add_custom_command (OUTPUT kxover-libdir-asn1
# 	COMMAND cmake -E make_directory ${KXOVER_LIBDIR}/asn1)

add_custom_command (OUTPUT ${KXOVER_DOCDIR}
	COMMAND cmake -E make_directory ${KXOVER_DOCDIR})

add_custom_command (OUTPUT ${QUICKDER_INCDIR}
	COMMAND cmake -E make_directory ${QUICKDER_INCDIR})

#
# Targets deriving Erlang code from the Petri Nets perpetuum/*.pnml
#

set (OUTPUTFILES)
foreach (SPEC ${SPECNAMES})

	set (OUTPUTFILES ${OUTPUTFILES}
		#NONEED# ${KXOVER_LIBDIR}/asn1/${SPEC}.asn1
		${KXOVER_DOCDIR}/${SPEC}.md
		${QUICKDER_INCDIR}/${SPEC}.h
		#NONEED# ${KXOVER_LIBDIR}/asn1/${SPEC}.py
	)

	#DEPENDS# add_custom_command (OUTPUT ${KXOVER_LIBDIR}/asn1/${SPEC}.asn1
	#DEPENDS# 	COMMAND cmake -E copy ${CMAKE_CURRENT_SOURCE_DIR}/${SPEC}.asn1 ${KXOVER_LIBDIR}/asn1/${SPEC}.asn1
	#DEPENDS# 	DEPENDS kxover-libdir-asn1 ${CMAKE_CURRENT_SOURCE_DIR}/${SPEC}.asn1)

	add_custom_command (OUTPUT ${KXOVER_DOCDIR}/${SPEC}.md
		COMMAND asn1literate ${CMAKE_CURRENT_SOURCE_DIR}/${SPEC}.asn1 ${KXOVER_DOCDIR}/${SPEC}.md
		DEPENDS ${KXOVER_DOCDIR})

	add_custom_command (OUTPUT ${QUICKDER_INCDIR}/${SPEC}.h
		COMMAND asn2quickder -l c -I ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/${SPEC}.asn1
		WORKING_DIRECTORY ${QUICKDER_INCDIR}
		DEPENDS ${QUICKDER_INCDIR})

	#DEPENDS# add_custom_command (OUTPUT ${KXOVER_LIBDIR}/asn1/${SPEC}.py
	#DEPENDS# 	COMMAND asn2quickder -l python -I ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/${SPEC}.asn1
	#DEPENDS# 	WORKING_DIRECTORY ${KXOVER_LIBDIR}/asn1
	#DEPENDS# 	DEPENDS kxover-libdir-asn1 ${CMAKE_CURRENT_SOURCE_DIR}/${SPEC}.asn1)

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

