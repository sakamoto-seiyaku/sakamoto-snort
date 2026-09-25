#ifndef T17_ASSERT_H
#define T17_ASSERT_H
#include <assert.h>
#define serverAssert assert
#define serverPanic(...) abort()
#endif
