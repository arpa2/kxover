# Various tests to the code, both unit and full runs


enable_testing ()

#
# BUILD TEST PROGRAMS
#

include_directories (${CMAKE_SOURCE_DIR}/src)

add_executable (udpwrap_test
	udpwrap_test.c
	${CMAKE_SOURCE_DIR}/src/socket.c
	${CMAKE_SOURCE_DIR}/src/backend.c
	${CMAKE_SOURCE_DIR}/src/udpwrap.c)

target_link_libraries (udpwrap_test ev)

#
# TEST REGISTRATION
#

set (py_setenv    ${CMAKE_COMMAND} -E env PYTHONPATH=${CMAKE_CURRENT_SOURCE_DIR}:${CMAKE_CURRENT_BINARY_DIR}:${_ppath})
set (pypeline     python ${CMAKE_CURRENT_SOURCE_DIR}/pypeline)
set (fakekdc      python ${CMAKE_CURRENT_SOURCE_DIR}/fakekdc)
set (udpclient    python ${CMAKE_CURRENT_SOURCE_DIR}/udpclient)
set (udpwrap_test        ${CMAKE_CURRENT_BINARY_DIR}/udpwrap_test)

add_test (NAME t_pypeline COMMAND ${py_setenv} ${pypeline}
	${fakekdc}   IP:KDC UDP:KDC bin/krb5-as-req1.der bin/krb5-as-rep1.der bin/krb5-as-req2.der bin/krb5-as-rep2.der
	--
	${udpclient} IP:KDC UDP:KDC bin/krb5-as-req1.der bin/krb5-as-rep1.der bin/krb5-as-req2.der bin/krb5-as-rep2.der
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_test (NAME t_udpwrap COMMAND ${py_setenv} ${pypeline}
	${fakekdc} IP:KDC UDP:KDC bin/krb5-as-req1.der bin/krb5-as-rep1.der bin/krb5-as-req2.der bin/krb5-as-rep2.der
	--
	${udpwrap_test} IP:FRONT UDP:FRONT IP:KDC UDP:KDC
	--
	${udpclient} IP:FRONT UDP:FRONT bin/krb5-as-req1.der bin/krb5-as-rep1.der bin/krb5-as-req2.der bin/krb5-as-rep2.der
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

# add_test (NAME t_tcpwrap
# 	COMMAND TODO
# 	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})



