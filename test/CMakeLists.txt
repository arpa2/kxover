# Various tests to the code, both unit and full runs


enable_testing ()

#
# BUILD TEST PROGRAMS
#

include_directories (${CMAKE_SOURCE_DIR}/src)


add_executable (test_udpwrap
	test_udpwrap.c
	${CMAKE_SOURCE_DIR}/src/socket.c
	${CMAKE_SOURCE_DIR}/src/backend.c
	${CMAKE_SOURCE_DIR}/src/udpwrap.c)

target_link_libraries (test_udpwrap ev)


add_executable (test_tcpwrap
	test_tcpwrap.c
	${CMAKE_SOURCE_DIR}/src/socket.c
	${CMAKE_SOURCE_DIR}/src/faketls.c
	${CMAKE_SOURCE_DIR}/src/backend.c
	${CMAKE_SOURCE_DIR}/src/tcpwrap.c)

target_link_libraries (test_tcpwrap ev)


add_executable (test_kxclient
	test_kxclient.c
	${CMAKE_SOURCE_DIR}/src/kxover.c
	${CMAKE_SOURCE_DIR}/src/socket.c
	${CMAKE_SOURCE_DIR}/src/faketls.c
	${CMAKE_SOURCE_DIR}/src/backend.c)

message (target_link_libraries (test_kxclient ${Unbound_LIBRARIES} ${Quick-DER_LIBRARIES} ev))
target_link_libraries (test_kxclient ${Unbound_LIBRARIES} ${Quick-DER_LIBRARIES} ev)


#
# TEST REGISTRATION
#

set (py_setenv ${CMAKE_COMMAND} -E env PYTHONPATH=${CMAKE_CURRENT_SOURCE_DIR}:${CMAKE_CURRENT_BINARY_DIR}:${_ppath})
set (pypeline       python ${CMAKE_CURRENT_SOURCE_DIR}/pypeline)
set (fakekdc_udp    python ${CMAKE_CURRENT_SOURCE_DIR}/fakekdc_udp)
set (fakekdc_tcp    python ${CMAKE_CURRENT_SOURCE_DIR}/fakekdc_tcp)
set (client_udp     python ${CMAKE_CURRENT_SOURCE_DIR}/client_udp)
set (client_tcp     python ${CMAKE_CURRENT_SOURCE_DIR}/client_tcp)
set (client_faketls python ${CMAKE_CURRENT_SOURCE_DIR}/client_tcp --fake-tls)
set (demo_hosts     python ${CMAKE_CURRENT_SOURCE_DIR}/demo-hosts)
set (test_udpwrap          ${CMAKE_CURRENT_BINARY_DIR}/test_udpwrap)
set (test_tcpwrap          ${CMAKE_CURRENT_BINARY_DIR}/test_tcpwrap)
set (test_kxclient         ${CMAKE_CURRENT_BINARY_DIR}/test_kxclient)

set (test_bin ${CMAKE_CURRENT_SOURCE_DIR}/bin)
set (dnssec_root_key $<SHELL_PATH:${test_bin}/dnssec-root-key>)
set (krb_as_flow $<SHELL_PATH:${test_bin}/krb5-as-req1.der> $<SHELL_PATH:${test_bin}/krb5-as-rep1.der> $<SHELL_PATH:${test_bin}/krb5-as-req2.der> $<SHELL_PATH:${test_bin}/krb5-as-rep2.der>)

add_test (NAME t_pypeline COMMAND ${py_setenv} ${pypeline}
	${client_udp} IP:KDC UDP:KDC ${krb_as_flow}
	--
	${fakekdc_udp}   IP:KDC UDP:KDC ${krb_as_flow}
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_test (NAME t_udpwrap COMMAND ${py_setenv} ${pypeline}
	${client_udp} IP:FRONT UDP:FRONT ${krb_as_flow}
	--
	${test_udpwrap} IP:FRONT UDP:FRONT IP:KDC UDP:KDC SIG:HUP
	--
	${fakekdc_udp} IP:KDC UDP:KDC ${krb_as_flow}
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_test (NAME t_tcpwrap COMMAND ${py_setenv} ${pypeline}
	${client_tcp} IP:FRONT UDP:FRONT ${krb_as_flow}
	--
	${test_tcpwrap} IP:FRONT UDP:FRONT IP:KDC UDP:KDC SIG:HUP
	--
	${fakekdc_udp} IP:KDC UDP:KDC  ${krb_as_flow}
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

if (FAKE_TLS)
# This test is like t_tcpwrap, but the client_faketls does a STARTTLS exchange before acting like the client_tcp
add_test (NAME t_tlswrap_fake COMMAND ${py_setenv} ${pypeline}
	${client_faketls} IP:FRONT UDP:FRONT ${krb_as_flow}
	--
	${test_tcpwrap} IP:FRONT UDP:FRONT IP:KDC UDP:KDC SIG:HUP
	--
	${fakekdc_udp} IP:KDC UDP:KDC ${krb_as_flow}
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
else()
# No test for real TLS yet
endif()

add_test (NAME t_127_0_0_1 COMMAND ${py_setenv} ${pypeline}
	${client_udp} 127.0.0.1 77 ${krb_as_flow}
	--
	${fakekdc_udp} 127.0.0.1 77 ${krb_as_flow}
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_test (NAME t_kxclient COMMAND ${py_setenv} ${pypeline}
	${demo_hosts} FILE:HOSTS localhost.demo.arpa2.org IP:KDC
	--
	${test_kxclient} PIXIE.DEMO.ARPA2.ORG UNICORN.DEMO.ARPA2.ORG IP:KDC UDP:KDC ${dnssec_root_key} FILE:HOSTS
	--
	${fakekdc_tcp} --tcp IP:KDC 77 bin/krb5-as-req1.der bin/krb5-as-rep1.der
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})



