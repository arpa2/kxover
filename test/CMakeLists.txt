# Various tests to the code, both unit and full runs


enable_testing ()

#
# BUILD TEST PROGRAMS
#

add_executable (udpwrap_test
	udpwrap_test.c
	${CMAKE_SOURCE_DIR}/src/backend.c
	${CMAKE_SOURCE_DIR}/src/udpwrap.c)

target_link_libraries (udpwrap_test ev)

#
# TEST REGISTRATION
#

set (test_pype ${CMAKE_COMMAND} -E env PYTHONPATH=${CMAKE_CURRENT_SOURCE_DIR}:${_ppath} python ./pypeline)

add_test (NAME t_pypeline
	COMMAND ${test_pype}
		./fakekdc   8888 bin/krb5-as-req1.der bin/krb5-as-rep1.der bin/krb5-as-req2.der bin/krb5-as-rep2.der
	--
		./udpclient 8888 bin/krb5-as-req1.der bin/krb5-as-rep1.der bin/krb5-as-req2.der bin/krb5-as-rep2.der
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

# add_test (NAME t_udpwrap
# COMMAND udpwrap_test
# WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

# add_test (NAME t_tcpwrap
# 	COMMAND TODO
# 	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})



