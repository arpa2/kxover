# Various tests to the code, both unit and full runs


enable_testing ()

#
# BUILD TEST PROGRAMS
#

set (SRC ${CMAKE_SOURCE_DIR}/src)

include_directories (${SRC})

add_definitions (-DBACKEND_POOLSIZE=${BACKEND_POOLSIZE} ${Kerberos5_DEFINITIONS})


add_executable (krb5-entropy
	krb5-entropy.c
	${SRC}/mitkrb5.c)

target_link_libraries (krb5-entropy ${Kerberos5_LIBRARIES} ${Quick-DER_LIBRARIES})


add_executable (test_udpwrap
	test_udpwrap.c
	${SRC}/socket.c
	${SRC}/backend.c
	${SRC}/udpwrap.c)

target_link_libraries (test_udpwrap ev)


add_executable (test_tcpwrap
	test_tcpwrap.c
	${SRC}/socket.c
	${SRC}/faketls.c
	${SRC}/kxover.c
	${SRC}/backend.c
	${SRC}/tcpwrap.c
	${SRC}/mitkrb5.c)

target_link_libraries (test_tcpwrap ${Unbound_LIBRARIES} ${Kerberos5_LIBRARIES} ${Quick-DER_LIBRARIES} ev)


add_executable (test_kxclient
	test_kxclient.c
	${SRC}/kxover.c
	${SRC}/socket.c
	${SRC}/faketls.c
	${SRC}/mitkrb5.c)

target_link_libraries (test_kxclient ${Unbound_LIBRARIES} ${Kerberos5_LIBRARIES} ${Quick-DER_LIBRARIES} ev)


add_executable (test_kxserver
	test_kxserver.c
	${SRC}/kxover.c
	${SRC}/socket.c
	${SRC}/faketls.c
	${SRC}/mitkrb5.c)

target_link_libraries (test_kxserver ${Unbound_LIBRARIES} ${Kerberos5_LIBRARIES} ${Quick-DER_LIBRARIES} ev)


#
# TEST REGISTRATION
#

set (valgrind       valgrind --log-file=${CMAKE_BINARY_DIR}/valgrind.log)
set (py_setenv             ${CMAKE_COMMAND} -E env PYTHONPATH=${CMAKE_CURRENT_SOURCE_DIR}:${CMAKE_CURRENT_BINARY_DIR}:${_ppath})
set (pypeline       python ${CMAKE_CURRENT_SOURCE_DIR}/pypeline)
set (fakekdc_udp    python ${CMAKE_CURRENT_SOURCE_DIR}/fakekdc_udp)
set (fakekdc_tcp    python ${CMAKE_CURRENT_SOURCE_DIR}/fakekdc_tcp)
set (client_udp     python ${CMAKE_CURRENT_SOURCE_DIR}/client_udp)
set (client_tcp     python ${CMAKE_CURRENT_SOURCE_DIR}/client_tcp)
set (client_faketls python ${CMAKE_CURRENT_SOURCE_DIR}/client_tcp --fake-tls)
set (demo_hosts     python ${CMAKE_CURRENT_SOURCE_DIR}/demo-hosts)
set (dot_timer      python ${CMAKE_CURRENT_SOURCE_DIR}/dot-timer)
set (test_udpwrap          ${CMAKE_CURRENT_BINARY_DIR}/test_udpwrap)
set (test_tcpwrap          ${CMAKE_CURRENT_BINARY_DIR}/test_tcpwrap)
set (test_kxclient         ${CMAKE_CURRENT_BINARY_DIR}/test_kxclient)
set (test_kxserver         ${CMAKE_CURRENT_BINARY_DIR}/test_kxserver)

set (test_bin ${CMAKE_CURRENT_SOURCE_DIR}/bin)
set (dnssec_root_key $<SHELL_PATH:${test_bin}/dnssec-root-key>)
set (krb_as_flow $<SHELL_PATH:${test_bin}/krb5-as-req1.der> $<SHELL_PATH:${test_bin}/krb5-as-rep1.der> $<SHELL_PATH:${test_bin}/krb5-as-req2.der> $<SHELL_PATH:${test_bin}/krb5-as-rep2.der>)

add_test (NAME t_entropy COMMAND ${CMAKE_CURRENT_BINARY_DIR}/krb5-entropy)

add_test (NAME t_pypeline COMMAND ${py_setenv} ${pypeline}
	${client_udp} IP:KDC UDP:KDC ${krb_as_flow}
	--
	${fakekdc_udp}   IP:KDC UDP:KDC ${krb_as_flow}
	--
	${dot_timer} 0.2 SIG:HUP
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_test (NAME t_udpwrap COMMAND ${py_setenv} ${pypeline}
	${client_udp} IP:FRONT UDP:FRONT ${krb_as_flow}
	--
	${test_udpwrap} IP:FRONT UDP:FRONT IP:KDC UDP:KDC SIG:HUP
	--
	${fakekdc_udp} IP:KDC UDP:KDC ${krb_as_flow}
	--
	${dot_timer} 0.2 SIG:HUP
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_test (NAME t_tcpwrap COMMAND ${py_setenv} ${pypeline}
	${client_tcp} IP:FRONT UDP:FRONT ${krb_as_flow}
	--
	${test_tcpwrap} IP:FRONT UDP:FRONT IP:KDC UDP:KDC ${dnssec_root_key} FILE:IGNORE SIG:HUP
	--
	${fakekdc_udp} IP:KDC UDP:KDC  ${krb_as_flow}
	--
	${dot_timer} 0.2 SIG:HUP
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

if (FAKE_TLS)
# This test is like t_tcpwrap, but the client_faketls does a STARTTLS exchange before acting like the client_tcp
add_test (NAME t_tlswrap_fake COMMAND ${py_setenv} ${pypeline}
	${client_faketls} IP:FRONT UDP:FRONT ${krb_as_flow}
	--
	${test_tcpwrap} IP:FRONT UDP:FRONT IP:KDC UDP:KDC ${dnssec_root_key} FILE:IGNORE SIG:HUP
	--
	${fakekdc_udp} IP:KDC UDP:KDC ${krb_as_flow}
	--
	${dot_timer} 0.2 SIG:HUP
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
else()
# No test for real TLS yet
endif()

add_test (NAME t_127_0_0_1 COMMAND ${py_setenv} ${pypeline}
	${client_udp} 127.0.0.1 77 ${krb_as_flow}
	--
	${fakekdc_udp} 127.0.0.1 77 ${krb_as_flow}
	--
	${dot_timer} 0.2 SIG:HUP
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

if (0)
if (ONLINE_TESTING)
#TODO# We used test_tcpwrap instead of fakekdc_tcp, but this now recognised KXOVER
#TODO# t_kxclient patched out for now because test_tcpwrap fails
#TODO# The following test is not active; we can pass traffic to client+server
add_test (NAME t_kxclient COMMAND ${py_setenv} ${pypeline}
	${valgrind} ${test_kxclient} PIXIE.DEMO.ARPA2.ORG UNICORN.DEMO.ARPA2.ORG ${dnssec_root_key} FILE:HOSTS
	--
	${test_tcpwrap} IP:KDC 77 IP:KDC UDP:KDC77 ${dnssec_root_key} FILE:HOSTS SIG:HUP
	--
	${fakekdc_udp} IP:KDC UDP:KDC77 bin/krb5-as-req1.der bin/krb5-as-rep1.der
	--
	${dot_timer} 0.2 SIG:HUP
	--
	${demo_hosts} FILE:HOSTS kdc.pixie.arpa2.lab IP:KDC kdc.unicorn.arpa2.lab IP:KDC
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
endif ()
endif ()

if (0)
if (ONLINE_TESTING)
#TODO# The following test is not active; we can pass traffic to client+server
add_test (NAME t_kxserver COMMAND ${py_setenv} ${pypeline}
	${test_kxclient} UNICORN.DEMO.ARPA2.ORG ${dnssec_root_key} FILE:HOSTS
	--
	${dot_timer} 0.2 SIG:HUP
	--
	${demo_hosts} FILE:HOSTS kdc.pixie.arpa2.lab IP:KDC kdc.unicorn.arpa2.lab IP:KDC
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
endif ()
endif ()

# Combining t_kxclient and t_kxserver into one, t_kxover
if (ONLINE_TESTING)
add_test (NAME t_kxover COMMAND ${py_setenv} ${pypeline}
	${valgrind} ${test_kxclient} PIXIE.DEMO.ARPA2.ORG UNICORN.DEMO.ARPA2.ORG ${dnssec_root_key} FILE:HOSTS
	--
	${test_tcpwrap} IP:KDC 77 IP:KDC UDP:KDC77 ${dnssec_root_key} FILE:HOSTS SIG:HUP
	--
	${fakekdc_udp} IP:KDC UDP:KDC77 bin/krb5-as-req1.der bin/krb5-as-rep1.der
	--
	${dot_timer} 0.2 SIG:HUP
	--
	${demo_hosts} FILE:HOSTS kdc.pixie.arpa2.lab IP:KDC kdc.unicorn.arpa2.lab IP:KDC
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
endif ()


