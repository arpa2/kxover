
#
# Configuration Variables
#

set (BACKEND_POOLSIZE 512 CACHE STRING
	"Maximum number of concurrent queries to the local KDC that acts as the KXOVER backend"
)
add_definitions (-DBACKEND_POOLSIZE=${BACKEND_POOLSIZE})


#
# Source Files and Compiler Instructions
#


#TODO# add the libev library in a portable manner
#TODO# consider https://github.com/ksophocleous/libev
#HUH?# find_library (LIB_EV ev)
#HUH?# if ...${LIBEV-NOTFOUND}...

set (kxover_SRC
	backend.c
	udpwrap.c
	tcpwrap.c
	starttls.c
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

