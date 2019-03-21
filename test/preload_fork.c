/* LD_PRELOAD hook for fork.  is libunbound doing funny things? */

#include <assert.h>

#include <unistd.h>

int fork (void) {
	assert ("Call to fork()" == "Unexpected");
}

	
