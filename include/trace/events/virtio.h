#undef TRACE_SYSTEM
#define TRACE_SYSTEM virtio

#if !defined(_TRACE_VIRTIO_H) ||                                               \
	(defined(CONFIG_VIRTIO_BLK_TRACE) && defined(TRACE_HEADER_MULTI_READ))
#define _TRACE_VIRTIO_H

#include <linux/tracepoint.h>

#ifdef CONFIG_VIRTIO_BLK_TRACE
#define TRACE_VIRTIO(name)                                                     \
	TRACE_EVENT(virtio_queue_rq_##name, TP_PROTO(u32 type), TP_ARGS(type), \
		    TP_STRUCT__entry(__field(u32, type)),                      \
		    TP_fast_assign(__entry->type = type),                      \
		    TP_printk("0x%08lx", (unsigned long)__entry->type));
#else
#define TRACE_VIRTIO(name)                                                     \
	static __always_inline void trace_virtio_queue_rq_##name(u32)          \
	{                                                                      \
	}
#endif

TRACE_VIRTIO(enter)
TRACE_VIRTIO(switch)
TRACE_VIRTIO(start_rq)
TRACE_VIRTIO(map_sg)
TRACE_VIRTIO(add_req)
TRACE_VIRTIO(restore)

#endif /* _TRACE_VIRTIO_H */

#include <trace/define_trace.h>
