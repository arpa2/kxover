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


add_executable (tcpwrap_test
	tcpwrap_test.c
	${CMAKE_SOURCE_DIR}/src/socket.c
	${CMAKE_SOURCE_DIR}/src/faketls.c
	${CMAKE_SOURCE_DIR}/src/backend.c
	${CMAKE_SOURCE_DIR}/src/tcpwrap.c)

target_link_libraries (tcpwrap_test ev)


#
# TEST REGISTRATION
#

set (py_setenv ${CMAKE_COMMAND} -E env PYTHONPATH=${CMAKE_CURRENT_SOURCE_DIR}:${CMAKE_CURRENT_BINARY_DIR}:${_ppath})
set (pypeline      python ${CMAKE_CURRENT_SOURCE_DIR}/pypeline)
set (fakekdc       python ${CMAKE_CURRENT_SOURCE_DIR}/fakekdc)
set (udpclient     python ${CMAKE_CURRENT_SOURCE_DIR}/udpclient)
set (tcpclient     python ${CMAKE_CURRENT_SOURCE_DIR}/tcpclient)
set (faketlsclient python ${CMAKE_CURRENT_SOURCE_DIR}/tcpclient --fake-tls)
set (udpwrap_test         ${CMAKE_CURRENT_BINARY_DIR}/udpwrap_test)
set (tcpwrap_test         ${CMAKE_CURRENT_BINARY_DIR}/tcpwrap_test)

add_test (NAME t_pypeline COMMAND ${py_setenv} ${pypeline}
	${udpclient} IP:KDC UDP:KDC bin/krb5-as-req1.der bin/krb5-as-rep1.der bin/krb5-as-req2.der bin/krb5-as-rep2.der
	--
	${fakekdc}   IP:KDC UDP:KDC bin/krb5-as-req1.der bin/krb5-as-rep1.der bin/krb5-as-req2.der bin/krb5-as-rep2.der
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_test (NAME t_udpwrap COMMAND ${py_setenv} ${pypeline}
	${udpclient} IP:FRONT UDP:FRONT bin/krb5-as-req1.der bin/krb5-as-rep1.der bin/krb5-as-req2.der bin/krb5-as-rep2.der
	--
	${udpwrap_test} IP:FRONT UDP:FRONT IP:KDC UDP:KDC SIG:HUP
	--
	${fakekdc} IP:KDC UDP:KDC bin/krb5-as-req1.der bin/krb5-as-rep1.der bin/krb5-as-req2.der bin/krb5-as-rep2.der
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_test (NAME t_tcpwrap COMMAND ${py_setenv} ${pypeline}
	${tcpclient} IP:FRONT UDP:FRONT bin/krb5-as-req1.der bin/krb5-as-rep1.der bin/krb5-as-req2.der bin/krb5-as-rep2.der
	--
	${tcpwrap_test} IP:FRONT UDP:FRONT IP:KDC UDP:KDC SIG:HUP
	--
	${fakekdc} IP:KDC UDP:KDC bin/krb5-as-req1.der bin/krb5-as-rep1.der bin/krb5-as-req2.der bin/krb5-as-rep2.der
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

if (FAKE_TLS)
# This test is like t_tcpwrap, but the faketlsclient does a STARTTLS exchange before acting like the tcpclient
add_test (NAME t_tlswrap_fake COMMAND ${py_setenv} ${pypeline}
	${faketlsclient} IP:FRONT UDP:FRONT bin/krb5-as-req1.der bin/krb5-as-rep1.der bin/krb5-as-req2.der bin/krb5-as-rep2.der
	--
	${tcpwrap_test} IP:FRONT UDP:FRONT IP:KDC UDP:KDC SIG:HUP
	--
	${fakekdc} IP:KDC UDP:KDC bin/krb5-as-req1.der bin/krb5-as-rep1.der bin/krb5-as-req2.der bin/krb5-as-rep2.der
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
else()
# No test for real TLS yet
endif()



