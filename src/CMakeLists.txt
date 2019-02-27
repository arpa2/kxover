
#
# Configuration Variables
#

set (BACKEND_POOLSIZE 512 CACHE STRING
	"Maximum number of concurrent queries to the local KDC that acts as the KXOVER backend"
)
add_definitions (-DBACKEND_POOLSIZE=${BACKEND_POOLSIZE})

include_directories (${KXOVER_INCDIR})


option (FAKE_TLS
	"Bypass TLS for now; use plain TCP and claim OK on any tests"
	OFF)


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

set (kxover_SRC
	backend.c
	udpwrap.c
	tcpwrap.c
	${TLS_SOURCE}
	kxover.c
)

add_executable (kxover ${kxover_SRC})
target_link_libraries (kxover ev) # (... quick_der tlspool)


#
# Tests on Built Binaries
#


#
# Installation Details
#

