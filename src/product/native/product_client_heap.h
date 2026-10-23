/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_CLIENT_HEAP_H
#define SAKAMOTO_PRODUCT_CLIENT_HEAP_H

/* VAPI and the observation consumer coexist in the application process.
 * Every native client operation selects the same locked process heap, so
 * default VPP vectors keep their allocator across serialized caller threads.
 * The returned caller heap must be restored before returning to the caller.
 * No client destroys this process-lifetime heap. */
void *product_client_heap_enter (void);
void product_client_heap_leave (void *caller_heap);

#endif
