
#
# Configuration Variables
#

set (BACKEND_POOLSIZE 512 CACHE STRING
	"Maximum number of concurrent queries to the local KDC that acts as the KXOVER backend"
)
add_definitions (-DBACKEND_POOLSIZE=${BACKEND_POOLSIZE} ${Kerberos5_DEFINITIONS})


#
# Source Files and Compiler Instructions
#


#TODO# add the libev library in a portable manner
#TODO# consider https://github.com/ksophocleous/libev
#HUH?# find_library (LIB_EV ev)
#HUH?# if ...${LIBEV-NOTFOUND}...

if (FAKE_TLS)
	set (TLS_SOURCE "faketls.c")
elseif(FAKE_TLS)
	set (TLS_SOURCE "starttls.c")
endif(FAKE_TLS)

set (KRB_SOURCE "${Kerberos5_SYSTEM}.c")

# For now, kxover-daemon is a stand-alone program.  We may merge with the tool.
# One way of doing this is a large shared library with small front-end programs.
set (kxover-daemon_SRC
	backend.c
	udpwrap.c
	tcpwrap.c
	${TLS_SOURCE}
	kxover.c
	${KRB_SOURCE}
	socket.c
	main.c
)

# For now, kxover-client holds mostly the same sources as kxover-daemon.
# We can merge them later; as one binary with multiple names, perhaps.
set (kxover-client_SRC
	tool.c
	${KRB_SOURCE}
)

# The kxover-service and kxover-client share code, but differentiate on name.
set (kxover-service_SRC
	tool.c
	${KRB_SOURCE}
)

add_executable (kxover-daemon ${kxover-daemon_SRC})
target_link_libraries (kxover-daemon ${Unbound_LIBRARIES} ${Quick-DER_LIBRARIES} ${Kerberos5_LIBRARIES} ev) # (... tlspool)

add_executable (kxover-client ${kxover-client_SRC})
target_link_libraries (kxover-client ${Kerberos5_LIBRARIES} ${Quick-DER_LIBRARIES})

add_executable (kxover-service ${kxover-client_SRC})
target_link_libraries (kxover-service ${Kerberos5_LIBRARIES} ${Quick-DER_LIBRARIES})


#
# Tests on Built Binaries
#


#
# Installation Details
#

message ("Installing kxover executable into ${CMAKE_INSTALL_SBINDIR}")
install (PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/kxover
	DESTINATION ${CMAKE_INSTALL_SBINDIR}
	RENAME ${Kerberos5_SYSTEM}-kxover-server
)

