#undef TRACE_SYSTEM
#define TRACE_SYSTEM virtio

#if !defined(_TRACE_SUBSYS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_SUBSYS_H

#include <linux/tracepoint.h>

#define TRACE_VIRTIO(name)                                                     \
	TRACE_EVENT(virtio_queue_rq_##name, TP_PROTO(u32 type), TP_ARGS(type), \
		    TP_STRUCT__entry(__field(u32, type)),                      \
		    TP_fast_assign(__entry->type = type),                      \
		    TP_printk("0x%08lx", (unsigned long)__entry->type));

TRACE_VIRTIO(enter)
TRACE_VIRTIO(switch)
TRACE_VIRTIO(start_rq)
TRACE_VIRTIO(map_sg)
TRACE_VIRTIO(add_req)
TRACE_VIRTIO(restore)

#endif /* _TRACE_SUBSYS_H */

#include <trace/define_trace.h>
