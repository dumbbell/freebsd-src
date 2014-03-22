/**
 * \file drmP.h
 * Private header for Direct Rendering Manager
 *
 * \author Rickard E. (Rik) Faith <faith@valinux.com>
 * \author Gareth Hughes <gareth@valinux.com>
 */

/*
 * Copyright 1999 Precision Insight, Inc., Cedar Park, Texas.
 * Copyright 2000 VA Linux Systems, Inc., Sunnyvale, California.
 * Copyright (c) 2009-2010, Code Aurora Forum.
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * VA LINUX SYSTEMS AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#ifndef _DRM_P_H_
#define _DRM_P_H_

#if defined(_KERNEL) || defined(__KERNEL__)

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/sglist.h>
#include <sys/stat.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/fcntl.h>
#include <sys/uio.h>
#include <sys/filio.h>
#include <sys/rwlock.h>
#include <sys/selinfo.h>
#include <sys/sysctl.h>
#include <sys/bus.h>
#include <sys/queue.h>
#include <sys/signalvar.h>
#include <sys/poll.h>
#include <sys/sbuf.h>
#include <sys/taskqueue.h>
#include <sys/tree.h>
#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>
#include <vm/vm_param.h>
#include <vm/vm_phys.h>
#include <machine/param.h>
#include <machine/pmap.h>
#include <machine/bus.h>
#include <machine/resource.h>
#if defined(__i386__) || defined(__amd64__)
#include <machine/specialreg.h>
#endif
#include <machine/sysarch.h>
#include <sys/endian.h>
#include <sys/mman.h>
#include <sys/rman.h>
#include <sys/memrange.h>
#include <dev/agp/agpvar.h>
#include <sys/agpio.h>
#include <sys/mutex.h>
#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>
#include <sys/selinfo.h>
#include <sys/bus.h>

#include <dev/drm2/drm.h>
#include <dev/drm2/drm_sarea.h>

#include <dev/drm2/drm_atomic.h>
#include <dev/drm2/drm_internal.h>
#include <dev/drm2/drm_linux_list.h>
#include <dev/drm2/drm_gem_names.h>

struct drm_file;
struct drm_device;

#include <dev/drm2/drm_os_freebsd.h>
#include <dev/drm2/drm_hashtab.h>
#include <dev/drm2/drm_mm.h>

#include "opt_compat.h"
#include "opt_drm.h"
#include "opt_syscons.h"
#ifdef DRM_DEBUG
#undef DRM_DEBUG
#define DRM_DEBUG_DEFAULT_ON 1
#endif /* DRM_DEBUG */

#define	DRM_DEBUGBITS_DEBUG		0x1
#define	DRM_DEBUGBITS_KMS		0x2
#define	DRM_DEBUGBITS_FAILED_IOCTL	0x4

#undef DRM_LINUX
#define DRM_LINUX 0

/***********************************************************************/
/** \name DRM template customization defaults */
/*@{*/

/* driver capabilities and requirements mask */
#define DRIVER_USE_AGP     0x1
#define DRIVER_REQUIRE_AGP 0x2
#define DRIVER_USE_MTRR    0x4
#define DRIVER_PCI_DMA     0x8
#define DRIVER_SG          0x10
#define DRIVER_HAVE_DMA    0x20
#define DRIVER_HAVE_IRQ    0x40
#define DRIVER_IRQ_SHARED  0x80
#define DRIVER_IRQ_VBL     0x100
#define DRIVER_DMA_QUEUE   0x200
#define DRIVER_FB_DMA      0x400
#define DRIVER_IRQ_VBL2    0x800
#define DRIVER_GEM         0x1000
#define DRIVER_MODESET     0x2000
#define DRIVER_PRIME       0x4000


#define DRM_KERNEL_CONTEXT    0	 /* Change drm_resctx if changed	  */
#define DRM_RESERVED_CONTEXTS 1	 /* Change drm_resctx if changed	  */

#define	DRM_GEM_MAPPING_MASK	(3ULL << 62)
#define	DRM_GEM_MAPPING_KEY	(2ULL << 62) /* Non-canonical address form */
#define	DRM_GEM_MAX_IDX		0x3fffff
#define	DRM_GEM_MAPPING_IDX(o)	(((o) >> 40) & DRM_GEM_MAX_IDX)
#define	DRM_GEM_MAPPING_OFF(i)	(((uint64_t)(i)) << 40)
#define	DRM_GEM_MAPPING_MAPOFF(o) \
    ((o) & ~(DRM_GEM_MAPPING_OFF(DRM_GEM_MAX_IDX) | DRM_GEM_MAPPING_KEY))

MALLOC_DECLARE(DRM_MEM_DMA);
MALLOC_DECLARE(DRM_MEM_SAREA);
MALLOC_DECLARE(DRM_MEM_DRIVER);
MALLOC_DECLARE(DRM_MEM_MAGIC);
MALLOC_DECLARE(DRM_MEM_MINOR);
MALLOC_DECLARE(DRM_MEM_IOCTLS);
MALLOC_DECLARE(DRM_MEM_MAPS);
MALLOC_DECLARE(DRM_MEM_BUFS);
MALLOC_DECLARE(DRM_MEM_SEGS);
MALLOC_DECLARE(DRM_MEM_PAGES);
MALLOC_DECLARE(DRM_MEM_FILES);
MALLOC_DECLARE(DRM_MEM_QUEUES);
MALLOC_DECLARE(DRM_MEM_CMDS);
MALLOC_DECLARE(DRM_MEM_MAPPINGS);
MALLOC_DECLARE(DRM_MEM_BUFLISTS);
MALLOC_DECLARE(DRM_MEM_AGPLISTS);
MALLOC_DECLARE(DRM_MEM_CTXBITMAP);
MALLOC_DECLARE(DRM_MEM_SGLISTS);
MALLOC_DECLARE(DRM_MEM_MM);
MALLOC_DECLARE(DRM_MEM_HASHTAB);
MALLOC_DECLARE(DRM_MEM_KMS);

SYSCTL_DECL(_hw_drm);

#define DRM_MAGIC_HASH_ORDER  4  /**< Size of key hash table. Must be power of 2. */

#define DRM_MAX_CTXBITMAP (PAGE_SIZE * 8)
#define DRM_MAP_HASH_OFFSET 0x10000000

/***********************************************************************/
/** \name Internal types and structures */
/*@{*/

#define DRM_ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))
#define DRM_MIN(a,b) ((a)<(b)?(a):(b))
#define DRM_MAX(a,b) ((a)>(b)?(a):(b))

#define DRM_IF_VERSION(maj, min) (maj << 16 | min)

#define __OS_HAS_AGP	1

#define DRM_DEV_MODE	(S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP)
#define DRM_DEV_UID	0
#define DRM_DEV_GID	0

#define wait_queue_head_t	atomic_t
#define DRM_WAKEUP(w)		wakeup((void *)w)
#define DRM_WAKEUP_INT(w)	wakeup(w)
#define DRM_INIT_WAITQUEUE(queue) do {(void)(queue);} while (0)

#define DRM_CURPROC		curthread
#define DRM_STRUCTPROC		struct thread
#define DRM_SPINTYPE		struct mtx
#define DRM_SPININIT(l,name)	mtx_init(l, name, NULL, MTX_DEF)
#define DRM_SPINUNINIT(l)	mtx_destroy(l)
#define DRM_SPINLOCK(l)		mtx_lock(l)
#define DRM_SPINUNLOCK(u)	mtx_unlock(u)
#define DRM_SPINLOCK_IRQSAVE(l, irqflags) do {		\
	mtx_lock(l);					\
	(void)irqflags;					\
} while (0)
#define DRM_SPINUNLOCK_IRQRESTORE(u, irqflags) mtx_unlock(u)
#define DRM_SPINLOCK_ASSERT(l)	mtx_assert(l, MA_OWNED)
#define DRM_LOCK(dev)		sx_xlock(&(dev)->dev_struct_lock)
#define DRM_UNLOCK(dev) 	sx_xunlock(&(dev)->dev_struct_lock)
#define	DRM_LOCK_SLEEP(dev, chan, flags, msg, timeout)			\
    (sx_sleep((chan), &(dev)->dev_struct_lock, (flags), (msg), (timeout)))
#if defined(INVARIANTS)
#define	DRM_LOCK_ASSERT(dev)	sx_assert(&(dev)->dev_struct_lock, SA_XLOCKED)
#define	DRM_UNLOCK_ASSERT(dev)	sx_assert(&(dev)->dev_struct_lock, SA_UNLOCKED)
#else
#define	DRM_LOCK_ASSERT(d)
#define	DRM_UNLOCK_ASSERT(d)
#endif

#define DRM_SYSCTL_HANDLER_ARGS	(SYSCTL_HANDLER_ARGS)

#define DRM_IRQ_ARGS		void *arg
typedef void			irqreturn_t;
#define IRQ_HANDLED		/* nothing */
#define IRQ_NONE		/* nothing */

enum {
	DRM_IS_NOT_AGP,
	DRM_IS_AGP,
	DRM_MIGHT_BE_AGP
};
#define DRM_AGP_MEM		struct agp_memory_info

/* DRM_SUSER returns true if the user is superuser */
#define DRM_AGP_FIND_DEVICE()	agp_find_device()
#define DRM_MTRR_WC		MDF_WRITECOMBINE
#define jiffies			ticks
#define	jiffies_to_msecs(x)	(((int64_t)(x)) * 1000 / hz)
#define	msecs_to_jiffies(x)	(((int64_t)(x)) * hz / 1000)
#define	time_after(a,b)		((long)(b) - (long)(a) < 0)
#define	time_after_eq(a,b)	((long)(b) - (long)(a) <= 0)

#define DRM_VERIFYAREA_READ( uaddr, size )		\
	(!useracc(__DECONST(caddr_t, uaddr), size, VM_PROT_READ))

#define DRM_COPY_TO_USER(user, kern, size) \
	copyout(kern, user, size)
#define DRM_COPY_FROM_USER(kern, user, size) \
	copyin(user, kern, size)
#define DRM_COPY_FROM_USER_UNCHECKED(arg1, arg2, arg3) 	\
	copyin(arg2, arg1, arg3)
#define DRM_COPY_TO_USER_UNCHECKED(arg1, arg2, arg3)	\
	copyout(arg2, arg1, arg3)
#define DRM_GET_USER_UNCHECKED(val, uaddr)		\
	((val) = fuword32(uaddr), 0)

#define DRM_GET_PRIV_SAREA(_dev, _ctx, _map) do {	\
	(_map) = (_dev)->context_sareas[_ctx];		\
} while(0)

#define LOCK_TEST_WITH_RETURN(dev, file_priv)				\
do {									\
	if (!_DRM_LOCK_IS_HELD(dev->lock.hw_lock->lock) ||		\
	     dev->lock.file_priv != file_priv) {			\
		DRM_ERROR("%s called without lock held\n",		\
			   __FUNCTION__);				\
		return EINVAL;						\
	}								\
} while (0)

/* Returns -errno to shared code */
#define DRM_WAIT_ON( ret, queue, timeout, condition )		\
for ( ret = 0 ; !ret && !(condition) ; ) {			\
	DRM_UNLOCK(dev);						\
	mtx_lock(&dev->irq_lock);				\
	if (!(condition))					\
	    ret = -mtx_sleep(&(queue), &dev->irq_lock, 		\
		PCATCH, "drmwtq", (timeout));			\
	mtx_unlock(&dev->irq_lock);				\
	DRM_LOCK(dev);						\
}

#define DRM_ERROR(fmt, ...) \
	printf("error: [" DRM_NAME ":pid%d:%s] *ERROR* " fmt,		\
	    DRM_CURRENTPID, __func__ , ##__VA_ARGS__)

#define DRM_INFO(fmt, ...)  printf("info: [" DRM_NAME "] " fmt , ##__VA_ARGS__)

#define DRM_DEBUG(fmt, ...) do {					\
	if ((drm_debug & DRM_DEBUGBITS_DEBUG) != 0)			\
		printf("[" DRM_NAME ":pid%d:%s] " fmt, DRM_CURRENTPID,	\
			__func__ , ##__VA_ARGS__);			\
} while (0)

#define DRM_DEBUG_KMS(fmt, ...) do {					\
	if ((drm_debug & DRM_DEBUGBITS_KMS) != 0)			\
		printf("[" DRM_NAME ":KMS:pid%d:%s] " fmt, DRM_CURRENTPID,\
			__func__ , ##__VA_ARGS__);			\
} while (0)

#define DRM_DEBUG_DRIVER(fmt, ...) do {					\
	if ((drm_debug & DRM_DEBUGBITS_KMS) != 0)			\
		printf("[" DRM_NAME ":KMS:pid%d:%s] " fmt, DRM_CURRENTPID,\
			__func__ , ##__VA_ARGS__);			\
} while (0)

#define	dev_err(dev, fmt, ...)						\
	device_printf((dev), "error: " fmt, ## __VA_ARGS__)
#define	dev_warn(dev, fmt, ...)						\
	device_printf((dev), "warning: " fmt, ## __VA_ARGS__)
#define	dev_info(dev, fmt, ...)						\
	device_printf((dev), "info: " fmt, ## __VA_ARGS__)
#define	dev_dbg(dev, fmt, ...) do {					\
	if ((drm_debug& DRM_DEBUGBITS_KMS) != 0) {			\
		device_printf((dev), "debug: " fmt, ## __VA_ARGS__);	\
	}								\
} while (0)

typedef struct drm_pci_id_list
{
	int vendor;
	int device;
	long driver_private;
	char *name;
} drm_pci_id_list_t;

struct drm_msi_blacklist_entry
{
	int vendor;
	int device;
};

typedef int drm_ioctl_t(struct drm_device *dev, void *data,
			struct drm_file *file_priv);

#define DRM_AUTH	0x1
#define	DRM_MASTER	0x2
#define DRM_ROOT_ONLY	0x4
#define DRM_CONTROL_ALLOW 0x8
#define DRM_UNLOCKED	0x10

struct drm_ioctl_desc {
	unsigned long cmd;
	int (*func)(struct drm_device *dev, void *data,
		    struct drm_file *file_priv);
	int flags;
	unsigned int cmd_drv;
};

/**
 * Creates a driver or general drm_ioctl_desc array entry for the given
 * ioctl, for use by drm_ioctl().
 */

#define DRM_IOCTL_DEF(ioctl, _func, _flags) \
	[DRM_IOCTL_NR(ioctl)] = {.cmd = ioctl, .func = _func, .flags = _flags, .cmd_drv = 0}

#define DRM_IOCTL_DEF_DRV(ioctl, _func, _flags)			\
	[DRM_IOCTL_NR(DRM_##ioctl)] = {.cmd = DRM_##ioctl, .func = _func, .flags = _flags, .cmd_drv = DRM_IOCTL_##ioctl}

struct drm_magic_entry {
	struct list_head head;
	struct drm_hash_item hash_item;
	struct drm_file *priv;
};

typedef struct drm_buf {
	int idx;		       /**< Index into master buflist */
	int total;		       /**< Buffer size */
	int order;		       /**< log-base-2(total) */
	int used;		       /**< Amount of buffer in use (for DMA) */
	unsigned long offset;	       /**< Byte offset (used internally) */
	void *address;		       /**< Address of buffer */
	unsigned long bus_address;     /**< Bus address of buffer */
	struct drm_buf *next;	       /**< Kernel-only: used for free list */
	__volatile__ int waiting;      /**< On kernel DMA queue */
	__volatile__ int pending;      /**< On hardware DMA queue */
	struct drm_file *file_priv;    /**< Private of holding file descr */
	int context;		       /**< Kernel queue for this buffer */
	int while_locked;	       /**< Dispatch this buffer while locked */
	enum {
		DRM_LIST_NONE = 0,
		DRM_LIST_FREE = 1,
		DRM_LIST_WAIT = 2,
		DRM_LIST_PEND = 3,
		DRM_LIST_PRIO = 4,
		DRM_LIST_RECLAIM = 5
	} list;			       /**< Which list we're on */

	int dev_priv_size;		 /**< Size of buffer private storage */
	void *dev_private;		 /**< Per-buffer private storage */
} drm_buf_t;

typedef struct drm_freelist {
	int		  initialized; /* Freelist in use		   */
	atomic_t	  count;       /* Number of free buffers	   */
	drm_buf_t	  *next;       /* End pointer			   */

	int		  low_mark;    /* Low water mark		   */
	int		  high_mark;   /* High water mark		   */
} drm_freelist_t;

typedef struct drm_dma_handle {
	void *vaddr;
	bus_addr_t busaddr;
	bus_dma_tag_t tag;
	bus_dmamap_t map;
} drm_dma_handle_t;

typedef struct drm_buf_entry {
	int		  buf_size;
	int		  buf_count;
	drm_buf_t	  *buflist;
	int		  seg_count;
	drm_dma_handle_t  **seglist;
	int		  page_order;

	drm_freelist_t	  freelist;
} drm_buf_entry_t;

/* Event queued up for userspace to read */
struct drm_pending_event {
	struct drm_event *event;
	struct list_head link;
	struct drm_file *file_priv;
	pid_t pid; /* pid of requester, no guarantee it's valid by the time
		      we deliver the event, for tracing only */
	void (*destroy)(struct drm_pending_event *event);
};

/* initial implementaton using a linked list - todo hashtab */
struct drm_prime_file_private {
	struct list_head head;
	struct mtx lock;
};

struct drm_file {
	int authenticated;
	pid_t pid;
	uid_t uid;
	drm_magic_t magic;
	unsigned long ioctl_count;
	struct list_head lhead;
	struct drm_minor *minor;
	unsigned long lock_count;

	void		 *driver_priv;
	struct drm_gem_names object_names;

	int is_master; /* this file private is a master for a minor */
	struct drm_master *master; /* master this node is currently associated with
				      N.B. not always minor->master */
	struct list_head fbs;

	struct selinfo event_poll;
	struct list_head event_list;
	int event_space;

	struct drm_prime_file_private prime;
};

typedef struct drm_lock_data {
	struct drm_hw_lock	*hw_lock;	/* Hardware lock		   */
	struct drm_file   *file_priv;   /* Unique identifier of holding process (NULL is kernel)*/
	int		  lock_queue;	/* Queue of blocked processes	   */
	unsigned long	  lock_time;	/* Time of last lock in jiffies	   */
	struct mtx	  spinlock;
} drm_lock_data_t;

/* This structure, in the struct drm_device, is always initialized while the
 * device
 * is open.  dev->dma_lock protects the incrementing of dev->buf_use, which
 * when set marks that no further bufs may be allocated until device teardown
 * occurs (when the last open of the device has closed).  The high/low
 * watermarks of bufs are only touched by the X Server, and thus not
 * concurrently accessed, so no locking is needed.
 */
typedef struct drm_device_dma {

	struct drm_buf_entry bufs[DRM_MAX_ORDER + 1];	/**< buffers, grouped by their size order */
	int buf_count;			/**< total number of buffers */
	struct drm_buf **buflist;		/**< Vector of pointers into drm_device_dma::bufs */
	int seg_count;
	int page_count;			/**< number of pages */
	unsigned long *pagelist;	/**< page list */
	unsigned long byte_count;
	enum {
		_DRM_DMA_USE_AGP = 0x01,
		_DRM_DMA_USE_SG = 0x02,
		_DRM_DMA_USE_FB = 0x04,
		_DRM_DMA_USE_PCI_RO = 0x08
	} flags;

} drm_device_dma_t;

typedef struct drm_agp_mem {
	void               *handle;
	unsigned long      bound; /* address */
	int                pages;
	struct drm_agp_mem *prev;
	struct drm_agp_mem *next;
} drm_agp_mem_t;

typedef struct drm_agp_head {
	device_t	   agpdev;
	struct agp_info    agp_info;
	const char         *chipset;
	drm_agp_mem_t      *memory;
	unsigned long      mode;
	int                enabled;
	int                acquired;
	unsigned long      base;
	int 		   agp_mtrr;
	int		   cant_use_aperture;
	unsigned long	   page_mask;
} drm_agp_head_t;

typedef struct drm_sg_mem {
	vm_offset_t vaddr;
	vm_paddr_t *busaddr;
	vm_pindex_t pages;
} drm_sg_mem_t;

struct drm_sigdata {
	int context;
	struct drm_hw_lock *lock;
};

/**
 * Kernel side of a mapping
 */
#define DRM_MAP_HANDLE_BITS	(sizeof(void *) == 4 ? 4 : 24)
#define DRM_MAP_HANDLE_SHIFT	(sizeof(void *) * 8 - DRM_MAP_HANDLE_BITS)

struct drm_local_map {
	resource_size_t offset;	 /**< Requested physical address (0 for SAREA)*/
	unsigned long size;	 /**< Requested physical size (bytes) */
	enum drm_map_type type;	 /**< Type of memory to map */
	enum drm_map_flags flags;	 /**< Flags */
	void *handle;		 /**< User-space: "Handle" to pass to mmap() */
				 /**< Kernel-space: kernel-virtual address */
	int mtrr;		 /**< MTRR slot used */

				  /* Private data                         */
	drm_dma_handle_t *dmah;
};

typedef struct drm_local_map drm_local_map_t;

/**
 * Mappings list
 */
struct drm_map_list {
	struct list_head head;		/**< list head */
	struct drm_hash_item hash;
	struct drm_local_map *map;	/**< mapping */
	uint64_t user_token;
	struct drm_master *master;
	struct drm_mm_node *file_offset_node;	/**< fake offset */
};

struct drm_vblank_info {
	wait_queue_head_t queue;	/* vblank wait queue */
	atomic_t count;			/* number of VBLANK interrupts */
					/* (driver must alloc the right number of counters) */
	atomic_t refcount;		/* number of users of vblank interrupts */
	u32 last;			/* protected by dev->vbl_lock, used */
					/* for wraparound handling */
	int enabled;			/* so we don't call enable more than */
					/* once per disable */
	int inmodeset;			/* Display driver is setting mode */
};

/* location of GART table */
#define DRM_ATI_GART_MAIN 1
#define DRM_ATI_GART_FB   2

#define DRM_ATI_GART_PCI 1
#define DRM_ATI_GART_PCIE 2
#define DRM_ATI_GART_IGP 3

struct drm_ati_pcigart_info {
	int gart_table_location;
	int gart_reg_if;
	void *addr;
	dma_addr_t bus_addr;
	dma_addr_t table_mask;
	dma_addr_t member_mask;
	struct drm_dma_handle *table_handle;
	drm_local_map_t mapping;
	int table_size;
	struct drm_dma_handle *dmah; /* handle for ATI PCIGART table */
};

/**
 * GEM specific mm private for tracking GEM objects
 */
struct drm_gem_mm {
	struct drm_open_hash offset_hash; /**< User token hash table for maps */
	struct unrhdr *idxunr;
};

struct drm_gem_object {
	/** Reference count of this object */
	u_int refcount;

	/** Handle count of this object. Each handle also holds a reference */
	u_int handle_count; /* number of handles on this object */

	/** Related drm device */
	struct drm_device *dev;

	/** File representing the shmem storage: filp in Linux parlance */
	vm_object_t vm_obj;

	bool on_map;
	struct drm_hash_item map_list;

	/**
	 * Size of the object, in bytes.  Immutable over the object's
	 * lifetime.
	 */
	size_t size;

	/**
	 * Global name for this object, starts at 1. 0 means unnamed.
	 * Access is covered by the object_name_lock in the related drm_device
	 */
	int name;

	/**
	 * Memory domains. These monitor which caches contain read/write data
	 * related to the object. When transitioning from one set of domains
	 * to another, the driver is called to ensure that caches are suitably
	 * flushed and invalidated
	 */
	uint32_t read_domains;
	uint32_t write_domain;

	/**
	 * While validating an exec operation, the
	 * new read/write domain values are computed here.
	 * They will be transferred to the above values
	 * at the point that any cache flushing occurs
	 */
	uint32_t pending_read_domains;
	uint32_t pending_write_domain;

	void *driver_private;

#ifdef FREEBSD_WIP
	/* dma buf exported from this GEM object */
	struct dma_buf *export_dma_buf;

	/* dma buf attachment backing this object */
	struct dma_buf_attachment *import_attach;
#endif /* FREEBSD_WIP */
};

#include "drm_crtc.h"

/* per-master structure */
struct drm_master {

	u_int refcount; /* refcount for this master */

	struct list_head head; /**< each minor contains a list of masters */
	struct drm_minor *minor; /**< link back to minor we are a master for */

	char *unique;			/**< Unique identifier: e.g., busid */
	int unique_len;			/**< Length of unique field */
	int unique_size;		/**< amount allocated */

	int blocked;			/**< Blocked due to VC switch? */

	/** \name Authentication */
	/*@{ */
	struct drm_open_hash magiclist;
	struct list_head magicfree;
	/*@} */

	struct drm_lock_data lock;	/**< Information on hardware lock */

	void *driver_priv; /**< Private structure for driver to use */
};

/* Size of ringbuffer for vblank timestamps. Just double-buffer
 * in initial implementation.
 */
#define DRM_VBLANKTIME_RBSIZE 2

/* Flags and return codes for get_vblank_timestamp() driver function. */
#define DRM_CALLED_FROM_VBLIRQ 1
#define DRM_VBLANKTIME_SCANOUTPOS_METHOD (1 << 0)
#define DRM_VBLANKTIME_INVBL             (1 << 1)

/* get_scanout_position() return flags */
#define DRM_SCANOUTPOS_VALID        (1 << 0)
#define DRM_SCANOUTPOS_INVBL        (1 << 1)
#define DRM_SCANOUTPOS_ACCURATE     (1 << 2)

#ifndef DMA_BIT_MASK
#define DMA_BIT_MASK(n) (((n) == 64) ? ~0ULL : (1ULL<<(n)) - 1)
#endif

#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))

struct drm_driver {
	int	(*load)(struct drm_device *, unsigned long flags);
	int	(*firstopen)(struct drm_device *);
	int	(*open)(struct drm_device *, struct drm_file *);
	void	(*preclose)(struct drm_device *, struct drm_file *file_priv);
	void	(*postclose)(struct drm_device *, struct drm_file *);
	void	(*lastclose)(struct drm_device *);
	int	(*unload)(struct drm_device *);
	int	(*dma_ioctl)(struct drm_device *dev, void *data,
			     struct drm_file *file_priv);
	void	(*dma_ready)(struct drm_device *);
	int	(*dma_quiescent)(struct drm_device *);
	int	(*dma_flush_block_and_flush)(struct drm_device *, int context,
					     enum drm_lock_flags flags);
	int	(*dma_flush_unblock)(struct drm_device *, int context,
				     enum drm_lock_flags flags);
	int	(*context_ctor)(struct drm_device *dev, int context);
	int	(*context_dtor)(struct drm_device *dev, int context);
	int	(*kernel_context_switch)(struct drm_device *dev, int old,
					 int new);
	int	(*kernel_context_switch_unlock)(struct drm_device *dev);
	void	(*irq_preinstall)(struct drm_device *dev);
	int	(*irq_postinstall)(struct drm_device *dev);
	void	(*irq_uninstall)(struct drm_device *dev);
	void	(*irq_handler)(DRM_IRQ_ARGS);

	u32	(*get_vblank_counter)(struct drm_device *dev, int crtc);
	int	(*enable_vblank)(struct drm_device *dev, int crtc);
	void	(*disable_vblank)(struct drm_device *dev, int crtc);
	int	(*get_scanout_position)(struct drm_device *dev, int crtc,
		    int *vpos, int *hpos);

	int	(*get_vblank_timestamp)(struct drm_device *dev, int crtc,
		    int *max_error, struct timeval *vblank_time,
		    unsigned flags);

	void (*set_version) (struct drm_device *dev,
			     struct drm_set_version *sv);

	/* Master routines */
	int	(*master_create)(struct drm_device *dev, struct drm_master *master);
	void	(*master_destroy)(struct drm_device *dev, struct drm_master *master);
        /**
	 * master_set is called whenever the minor master is set.
	 * master_drop is called whenever the minor master is dropped.
	 */

	int (*master_set)(struct drm_device *dev, struct drm_file *file_priv,
	    bool from_open);
	void (*master_drop)(struct drm_device *dev, struct drm_file *file_priv,
	    bool from_release);

	int	(*gem_init_object)(struct drm_gem_object *obj);
	void	(*gem_free_object)(struct drm_gem_object *obj);
	int	(*gem_open_object)(struct drm_gem_object *, struct drm_file *);
	void	(*gem_close_object)(struct drm_gem_object *, struct drm_file *);

	struct cdev_pager_ops *gem_pager_ops;

	int	(*dumb_create)(struct drm_file *file_priv,
		    struct drm_device *dev, struct drm_mode_create_dumb *args);
	int	(*dumb_map_offset)(struct drm_file *file_priv,
		    struct drm_device *dev, uint32_t handle, uint64_t *offset);
	int	(*dumb_destroy)(struct drm_file *file_priv,
		    struct drm_device *dev, uint32_t handle);

	int	(*sysctl_init)(struct drm_device *dev,
		    struct sysctl_ctx_list *ctx, struct sysctl_oid *top);
	void	(*sysctl_cleanup)(struct drm_device *dev);

	drm_pci_id_list_t *id_entry;	/* PCI ID, name, and chipset private */

	/**
	 * Called by \c drm_device_is_agp.  Typically used to determine if a
	 * card is really attached to AGP or not.
	 *
	 * \param dev  DRM device handle
	 *
	 * \returns
	 * One of three values is returned depending on whether or not the
	 * card is absolutely \b not AGP (return of 0), absolutely \b is AGP
	 * (return of 1), or may or may not be AGP (return of 2).
	 */
	int	(*device_is_agp) (struct drm_device * dev);

	struct drm_ioctl_desc *ioctls;
	int num_ioctls;
#ifdef COMPAT_FREEBSD32
	struct drm_ioctl_desc *compat_ioctls;
	int *num_compat_ioctls;
#endif

	int	buf_priv_size;

	int	major;
	int	minor;
	int	patchlevel;
	const char *name;		/* Simple driver name		   */
	const char *desc;		/* Longer driver name		   */
	const char *date;		/* Date of last major changes.	   */

	u32 driver_features;
	int dev_priv_size;
};

#define DRM_MINOR_UNASSIGNED 0
#define DRM_MINOR_LEGACY 1
#define DRM_MINOR_CONTROL 2
#define DRM_MINOR_RENDER 3

/**
 * DRM minor structure. This structure represents a drm minor number.
 */
struct drm_minor {
	int index;			/**< Minor device number */
	int type;                       /**< Control or render */
	struct cdev *device;		/**< Device number for mknod */
	device_t kdev;			/**< OS device */
	struct drm_device *dev;

	struct drm_master *master; /* currently active master for this node */
	struct list_head master_list;
	struct drm_mode_group mode_group;

	struct sigio *buf_sigio;	/* Processes waiting for SIGIO     */
};

/* mode specified on the command line */
struct drm_cmdline_mode {
	bool specified;
	bool refresh_specified;
	bool bpp_specified;
	int xres, yres;
	int bpp;
	int refresh;
	bool rb;
	bool interlace;
	bool cvt;
	bool margins;
	enum drm_connector_force force;
};


struct drm_pending_vblank_event {
	struct drm_pending_event base;
	int pipe;
	struct drm_event_vblank event;
};

/* Length for the array of resource pointers for drm_get_resource_*. */
#define DRM_MAX_PCI_RESOURCE	6

/**
 * DRM device structure. This structure represent a complete card that
 * may contain multiple heads.
 */
struct drm_device {
	struct drm_driver *driver;
	drm_pci_id_list_t *id_entry;	/* PCI ID, name, and chipset private */

	uint16_t pci_device;		/* PCI device id */
	uint16_t pci_vendor;		/* PCI vendor id */
	uint16_t pci_subdevice;		/* PCI subsystem device id */
	uint16_t pci_subvendor;		/* PCI subsystem vendor id */

	device_t	  dev;		/* Device instance from newbus     */
	int		  if_version;	/* Highest interface version set */

				/* Locks */
	struct mtx	  dma_lock;	/* protects dev->dma */
	struct mtx	  irq_lock;	/* protects irq condition checks */
	struct mtx	  count_lock;	/**< For inuse, drm_device::open_count, drm_device::buf_use */
	struct sx	  dev_struct_lock;
	DRM_SPINTYPE	  drw_lock;

	/** \name Usage Counters */
	/*@{ */
	int open_count;			/**< Outstanding files open */
	atomic_t ioctl_count;		/**< Outstanding IOCTLs pending */
	atomic_t vma_count;		/**< Outstanding vma areas open */
	int buf_use;			/**< Buffers in use -- cannot alloc */
	atomic_t buf_alloc;		/**< Buffer allocation in progress */
	/*@} */

	/** \name Performance counters */
	/*@{ */
	unsigned long counters;
	enum drm_stat_type types[15];
	atomic_t counts[15];
	/*@} */

	struct list_head filelist;

	/* Linked list of mappable regions. Protected by dev_lock */
	struct list_head  maplist;
	int map_count;			/**< Number of mappable regions */
	struct drm_open_hash map_hash;	/**< User token hash table for maps */

	/** \name Context handle management */
	/*@{ */
	struct list_head ctxlist;	/**< Linked list of context handles */
	int ctx_count;			/**< Number of context handles */
	struct mtx ctxlist_mutex;	/**< For ctxlist */

	/*@} */

	drm_local_map_t	  **context_sareas;
	int		  max_context;

	drm_lock_data_t	  lock;		/* Information on hardware lock	   */

				/* DMA queues (contexts) */
	drm_device_dma_t  *dma;		/* Optional pointer for DMA support */

	/** \name Context support */
	/*@{ */
	int irq_enabled;		/**< True if irq handler is enabled */
	atomic_t context_flag;		/**< Context swapping flag */
	atomic_t interrupt_flag;	/**< Interruption handler flag */
	atomic_t dma_flag;		/**< DMA dispatch flag */
	wait_queue_head_t context_wait;	/**< Processes waiting on ctx switch */
	int last_checked;		/**< Last context checked for DMA */
	int last_context;		/**< Last current context */
	unsigned long last_switch;	/**< jiffies at last context switch */
	/*@} */

				/* Context support */
	int		  irq;		/* Interrupt used by board	   */
	int		  msi_enabled;	/* MSI enabled */
	int		  irqrid;	/* Interrupt used by board */
	struct resource   *irqr;	/* Resource for interrupt used by board	   */
	void		  *irqh;	/* Handle from bus_setup_intr      */

	/* Storage of resource pointers for drm_get_resource_* */
	struct resource   *pcir[DRM_MAX_PCI_RESOURCE];
	int		  pcirid[DRM_MAX_PCI_RESOURCE];
	struct mtx	  pcir_lock;

	int		  pci_domain;
	int		  pci_bus;
	int		  pci_slot;
	int		  pci_func;

	int		  num_crtcs;

				/* Sysctl support */
	struct drm_sysctl_info *sysctl;
	int		  sysctl_node_idx;

	drm_agp_head_t    *agp;
	drm_sg_mem_t      *sg;  /* Scatter gather memory */
	unsigned long     *ctx_bitmap;
	void		  *dev_private;
	unsigned int	  agp_buffer_token;
	drm_local_map_t   *agp_buffer_map;

	struct drm_minor *control;		/**< Control node for card */
	struct drm_minor *primary;		/**< render type primary screen head */

	void		  *drm_ttm_bdev;
	struct unrhdr	  *drw_unrhdr;

	int vblank_disable_allowed;

	atomic_t *_vblank_count;        /**< number of VBLANK interrupts (driver must alloc the right number of counters) */
	struct timeval *_vblank_time;   /**< timestamp of current vblank_count (drivers must alloc right number of fields) */
	struct mtx vblank_time_lock;    /**< Protects vblank count and time updates during vblank enable/disable */
	struct mtx vbl_lock;
	atomic_t *vblank_refcount;      /* number of users of vblank interruptsper crtc */
	u32 *last_vblank;               /* protected by dev->vbl_lock, used */
					/* for wraparound handling */
	int *vblank_enabled;            /* so we don't call enable more than
					   once per disable */
	int *vblank_inmodeset;          /* Display driver is setting mode */
	u32 *last_vblank_wait;		/* Last vblank seqno waited per CRTC */
	struct callout vblank_disable_callout;

	u32 max_vblank_count;           /**< size of vblank counter register */

	struct list_head vblank_event_list;
	struct mtx	 event_lock;

        struct drm_mode_config mode_config;	/**< Current mode config */

	/* GEM part */
	struct sx	  object_name_lock;
	struct drm_gem_names object_names;
	void		 *mm_private;
	struct drm_sigdata sigdata;	   /**< For block_all_signals */

	void *sysctl_private;
	char busid_str[128];
	int modesetting;

	int switch_power_state;
};

#define DRM_SWITCH_POWER_ON 0
#define DRM_SWITCH_POWER_OFF 1
#define DRM_SWITCH_POWER_CHANGING 2

static __inline__ int drm_core_check_feature(struct drm_device *dev,
					     int feature)
{
	return ((dev->driver->driver_features & feature) ? 1 : 0);
}

int	drm_pci_get_irq(struct drm_device *dev);
void	drm_pci_free_irq(struct drm_device *dev);

static inline int drm_dev_to_irq(struct drm_device *dev)
{
	return drm_pci_get_irq(dev);
}

static inline int drm_core_has_MTRR(struct drm_device *dev)
{
	return drm_core_check_feature(dev, DRIVER_USE_MTRR);
}

#if __OS_HAS_AGP
static inline int drm_core_has_AGP(struct drm_device *dev)
{
	return drm_core_check_feature(dev, DRIVER_USE_AGP);
}
#else
#define drm_core_has_AGP(dev) (0)
#endif

enum dmi_field {
        DMI_NONE,
        DMI_BIOS_VENDOR,
        DMI_BIOS_VERSION,
        DMI_BIOS_DATE,
        DMI_SYS_VENDOR,
        DMI_PRODUCT_NAME,
        DMI_PRODUCT_VERSION,
        DMI_PRODUCT_SERIAL,
        DMI_PRODUCT_UUID,
        DMI_BOARD_VENDOR,
        DMI_BOARD_NAME,
        DMI_BOARD_VERSION,
        DMI_BOARD_SERIAL,
        DMI_BOARD_ASSET_TAG,
        DMI_CHASSIS_VENDOR,
        DMI_CHASSIS_TYPE,
        DMI_CHASSIS_VERSION,
        DMI_CHASSIS_SERIAL,
        DMI_CHASSIS_ASSET_TAG,
        DMI_STRING_MAX,
};

struct dmi_strmatch {
	unsigned char slot;
	char substr[79];
};

struct dmi_system_id {
        int (*callback)(const struct dmi_system_id *);
        const char *ident;
        struct dmi_strmatch matches[4];
};
#define	DMI_MATCH(a, b) {(a), (b)}
bool dmi_check_system(const struct dmi_system_id *);

/* Device setup support (drm_drv.c) */
extern struct sx drm_global_mutex;
int	drm_probe_helper(device_t kdev, drm_pci_id_list_t *idlist);
int	drm_attach_helper(device_t kdev, drm_pci_id_list_t *idlist,
	    struct drm_driver *driver);
void	drm_close(void *data);
int	drm_generic_detach(device_t kdev);
d_ioctl_t drm_ioctl;
d_open_t drm_open;
d_read_t drm_read;
d_poll_t drm_poll;
d_mmap_t drm_mmap;
int	drm_mmap_single(struct cdev *kdev, vm_ooffset_t *offset,
	    vm_size_t size, struct vm_object **obj_res, int nprot);
extern int drm_lastclose(struct drm_device *dev);
extern drm_local_map_t	*drm_getsarea(struct drm_device *dev);

void drm_event_wakeup(struct drm_pending_event *e);

int drm_add_busid_modesetting(struct drm_device *dev,
    struct sysctl_ctx_list *ctx, struct sysctl_oid *top);

#ifdef FREEBSD_WIP
extern int drm_gem_prime_handle_to_fd(struct drm_device *dev,
		struct drm_file *file_priv, uint32_t handle, uint32_t flags,
		int *prime_fd);
extern int drm_gem_prime_fd_to_handle(struct drm_device *dev,
		struct drm_file *file_priv, int prime_fd, uint32_t *handle);

extern int drm_prime_handle_to_fd_ioctl(struct drm_device *dev, void *data,
					struct drm_file *file_priv);
extern int drm_prime_fd_to_handle_ioctl(struct drm_device *dev, void *data,
					struct drm_file *file_priv);

#ifdef FREEBSD_WIP
/*
 * See drm_prime.c
 *   -- dumbbell@
 */
extern int drm_prime_sg_to_page_addr_arrays(struct sg_table *sgt, vm_page_t *pages,
					    dma_addr_t *addrs, int max_pages);
#endif /* FREEBSD_WIP */
extern struct sg_table *drm_prime_pages_to_sg(vm_page_t *pages, int nr_pages);
extern void drm_prime_gem_destroy(struct drm_gem_object *obj, struct sg_table *sg);


void drm_prime_init_file_private(struct drm_prime_file_private *prime_fpriv);
void drm_prime_destroy_file_private(struct drm_prime_file_private *prime_fpriv);
int drm_prime_add_imported_buf_handle(struct drm_prime_file_private *prime_fpriv, struct dma_buf *dma_buf, uint32_t handle);
int drm_prime_lookup_imported_buf_handle(struct drm_prime_file_private *prime_fpriv, struct dma_buf *dma_buf, uint32_t *handle);
void drm_prime_remove_imported_buf_handle(struct drm_prime_file_private *prime_fpriv, struct dma_buf *dma_buf);

int drm_prime_add_dma_buf(struct drm_device *dev, struct drm_gem_object *obj);
int drm_prime_lookup_obj(struct drm_device *dev, struct dma_buf *buf,
			 struct drm_gem_object **obj);
#endif /* FREEBSD_WIP */

/* Memory management support (drm_memory.c) */
int	drm_mtrr_add(unsigned long offset, size_t size, int flags);
int	drm_mtrr_del(int handle, unsigned long offset, size_t size, int flags);

int	drm_context_switch(struct drm_device *dev, int old, int new);
int	drm_context_switch_complete(struct drm_device *dev, int new);

int	drm_ctxbitmap_init(struct drm_device *dev);
void	drm_ctxbitmap_cleanup(struct drm_device *dev);
void	drm_ctxbitmap_free(struct drm_device *dev, int ctx_handle);
int	drm_ctxbitmap_next(struct drm_device *dev);

/* Locking IOCTL support (drm_lock.c) */
int	drm_lock_take(struct drm_lock_data *lock_data,
		      unsigned int context);
int	drm_lock_transfer(struct drm_lock_data *lock_data,
			  unsigned int context);
int	drm_lock_free(struct drm_lock_data *lock_data,
		      unsigned int context);
extern int drm_i_have_hw_lock(struct drm_device *dev, struct drm_file *file_priv);

/* Buffer management support (drm_bufs.c) */
unsigned long drm_get_resource_start(struct drm_device *dev,
				     unsigned int resource);
unsigned long drm_get_resource_len(struct drm_device *dev,
				   unsigned int resource);
extern int drm_addbufs_agp(struct drm_device *dev, struct drm_buf_desc * request);
extern int drm_addbufs_pci(struct drm_device *dev, struct drm_buf_desc * request);
extern int drm_addmap(struct drm_device *dev, resource_size_t offset,
		      unsigned int size, enum drm_map_type type,
		      enum drm_map_flags flags, struct drm_local_map **map_ptr);
extern int drm_addmap_ioctl(struct drm_device *dev, void *data,
			    struct drm_file *file_priv);
extern int drm_rmmap(struct drm_device *dev, struct drm_local_map *map);
extern int drm_rmmap_locked(struct drm_device *dev, struct drm_local_map *map);
extern int drm_rmmap_ioctl(struct drm_device *dev, void *data,
			   struct drm_file *file_priv);
extern int drm_addbufs(struct drm_device *dev, void *data,
		       struct drm_file *file_priv);
extern int drm_infobufs(struct drm_device *dev, void *data,
			struct drm_file *file_priv);
extern int drm_markbufs(struct drm_device *dev, void *data,
			struct drm_file *file_priv);
extern int drm_freebufs(struct drm_device *dev, void *data,
			struct drm_file *file_priv);
extern int drm_mapbufs(struct drm_device *dev, void *data,
		       struct drm_file *file_priv);
extern int drm_order(unsigned long size);

/* DMA support (drm_dma.c) */
int	drm_dma_setup(struct drm_device *dev);
void	drm_dma_takedown(struct drm_device *dev);
void	drm_free_buffer(struct drm_device *dev, drm_buf_t *buf);
void	drm_reclaim_buffers(struct drm_device *dev, struct drm_file *file_priv);
#define drm_core_reclaim_buffers drm_reclaim_buffers

/* IRQ support (drm_irq.c) */
int	drm_irq_install(struct drm_device *dev);
int	drm_irq_uninstall(struct drm_device *dev);
irqreturn_t drm_irq_handler(DRM_IRQ_ARGS);
void	drm_driver_irq_preinstall(struct drm_device *dev);
void	drm_driver_irq_postinstall(struct drm_device *dev);
void	drm_driver_irq_uninstall(struct drm_device *dev);

void	drm_vblank_pre_modeset(struct drm_device *dev, int crtc);
void	drm_vblank_post_modeset(struct drm_device *dev, int crtc);
int 	drm_modeset_ctl(struct drm_device *dev, void *data,
			struct drm_file *file_priv);

extern int drm_vblank_init(struct drm_device *dev, int num_crtcs);
extern int drm_wait_vblank(struct drm_device *dev, void *data,
			   struct drm_file *filp);
extern int drm_vblank_wait(struct drm_device *dev, unsigned int *vbl_seq);
extern u32 drm_vblank_count(struct drm_device *dev, int crtc);
extern u32 drm_vblank_count_and_time(struct drm_device *dev, int crtc,
				     struct timeval *vblanktime);
extern bool drm_handle_vblank(struct drm_device *dev, int crtc);
void drm_handle_vblank_events(struct drm_device *dev, int crtc);
extern int drm_vblank_get(struct drm_device *dev, int crtc);
extern void drm_vblank_put(struct drm_device *dev, int crtc);
extern void drm_vblank_off(struct drm_device *dev, int crtc);
extern void drm_vblank_cleanup(struct drm_device *dev);
extern u32 drm_get_last_vbltimestamp(struct drm_device *dev, int crtc,
				     struct timeval *tvblank, unsigned flags);
extern int drm_calc_vbltimestamp_from_scanoutpos(struct drm_device *dev,
						 int crtc, int *max_error,
						 struct timeval *vblank_time,
						 unsigned flags,
						 struct drm_crtc *refcrtc);
extern void drm_calc_timestamping_constants(struct drm_crtc *crtc);

struct timeval ns_to_timeval(const int64_t nsec);
int64_t timeval_to_ns(const struct timeval *tv);

/* AGP/PCI Express/GART support (drm_agpsupport.c) */
int	drm_device_is_agp(struct drm_device *dev);
int	drm_device_is_pcie(struct drm_device *dev);
drm_agp_head_t *drm_agp_init(void);
int	drm_agp_acquire(struct drm_device *dev);
int	drm_agp_release(struct drm_device *dev);
int	drm_agp_info(struct drm_device * dev, struct drm_agp_info *info);
int	drm_agp_enable(struct drm_device *dev, struct drm_agp_mode mode);
void	*drm_agp_allocate_memory(size_t pages, u32 type);
int	drm_agp_free_memory(void *handle);
int	drm_agp_bind_memory(void *handle, off_t start);
int	drm_agp_unbind_memory(void *handle);
int	drm_agp_alloc(struct drm_device *dev, struct drm_agp_buffer *request);
int	drm_agp_free(struct drm_device *dev, struct drm_agp_buffer *request);
int	drm_agp_bind(struct drm_device *dev, struct drm_agp_binding *request);
int	drm_agp_unbind(struct drm_device *dev, struct drm_agp_binding *request);

/* Scatter Gather Support (drm_scatter.c) */
void	drm_sg_cleanup(drm_sg_mem_t *entry);
int	drm_sg_alloc(struct drm_device *dev, struct drm_scatter_gather * request);

/* sysctl support (drm_sysctl.h) */
extern int		drm_sysctl_init(struct drm_device *dev);
extern int		drm_sysctl_cleanup(struct drm_device *dev);

/* ATI PCIGART support (ati_pcigart.c) */
int	drm_ati_pcigart_init(struct drm_device *dev,
				struct drm_ati_pcigart_info *gart_info);
int	drm_ati_pcigart_cleanup(struct drm_device *dev,
				struct drm_ati_pcigart_info *gart_info);

/* Cache management (drm_memory.c) */
void	drm_clflush_pages(vm_page_t *pages, unsigned long num_pages);

/* Locking IOCTL support (drm_drv.c) */
int	drm_lock(struct drm_device *dev, void *data,
		 struct drm_file *file_priv);
int	drm_unlock(struct drm_device *dev, void *data,
		   struct drm_file *file_priv);
int	drm_version(struct drm_device *dev, void *data,
		    struct drm_file *file_priv);
int	drm_setversion(struct drm_device *dev, void *data,
		       struct drm_file *file_priv);

/* Misc. IOCTL support (drm_ioctl.c) */
int	drm_irq_by_busid(struct drm_device *dev, void *data,
			 struct drm_file *file_priv);
int	drm_getunique(struct drm_device *dev, void *data,
		      struct drm_file *file_priv);
int	drm_setunique(struct drm_device *dev, void *data,
		      struct drm_file *file_priv);
int	drm_getmap(struct drm_device *dev, void *data,
		   struct drm_file *file_priv);
int	drm_getclient(struct drm_device *dev, void *data,
		      struct drm_file *file_priv);
int	drm_getstats(struct drm_device *dev, void *data,
		     struct drm_file *file_priv);
int	drm_getcap(struct drm_device *dev, void *data,
		     struct drm_file *file_priv);
int	drm_noop(struct drm_device *dev, void *data,
		 struct drm_file *file_priv);

/* Context IOCTL support (drm_context.c) */
int	drm_resctx(struct drm_device *dev, void *data,
		   struct drm_file *file_priv);
int	drm_addctx(struct drm_device *dev, void *data,
		   struct drm_file *file_priv);
int	drm_modctx(struct drm_device *dev, void *data,
		   struct drm_file *file_priv);
int	drm_getctx(struct drm_device *dev, void *data,
		   struct drm_file *file_priv);
int	drm_switchctx(struct drm_device *dev, void *data,
		      struct drm_file *file_priv);
int	drm_newctx(struct drm_device *dev, void *data,
		   struct drm_file *file_priv);
int	drm_rmctx(struct drm_device *dev, void *data,
		  struct drm_file *file_priv);
int	drm_setsareactx(struct drm_device *dev, void *data,
			struct drm_file *file_priv);
int	drm_getsareactx(struct drm_device *dev, void *data,
			struct drm_file *file_priv);

/* Authentication IOCTL support (drm_auth.c) */
int	drm_getmagic(struct drm_device *dev, void *data,
		     struct drm_file *file_priv);
int	drm_authmagic(struct drm_device *dev, void *data,
		      struct drm_file *file_priv);
int	drm_remove_magic(struct drm_master *master, drm_magic_t magic);

/* Buffer management support (drm_bufs.c) */
int	drm_addmap_ioctl(struct drm_device *dev, void *data,
			 struct drm_file *file_priv);
int	drm_rmmap_ioctl(struct drm_device *dev, void *data,
			struct drm_file *file_priv);
int	drm_addbufs(struct drm_device *dev, void *data,
		    struct drm_file *file_priv);
int	drm_infobufs(struct drm_device *dev, void *data,
		     struct drm_file *file_priv);
int	drm_markbufs(struct drm_device *dev, void *data,
		     struct drm_file *file_priv);
int	drm_freebufs(struct drm_device *dev, void *data,
		     struct drm_file *file_priv);
int	drm_mapbufs(struct drm_device *dev, void *data,
		    struct drm_file *file_priv);

/* DMA support (drm_dma.c) */
int	drm_dma(struct drm_device *dev, void *data, struct drm_file *file_priv);

/* IRQ support (drm_irq.c) */
int	drm_control(struct drm_device *dev, void *data,
		    struct drm_file *file_priv);

/* AGP/GART support (drm_agpsupport.c) */
int	drm_agp_acquire_ioctl(struct drm_device *dev, void *data,
			      struct drm_file *file_priv);
int	drm_agp_release_ioctl(struct drm_device *dev, void *data,
			      struct drm_file *file_priv);
int	drm_agp_enable_ioctl(struct drm_device *dev, void *data,
			     struct drm_file *file_priv);
int	drm_agp_info_ioctl(struct drm_device *dev, void *data,
			   struct drm_file *file_priv);
int	drm_agp_alloc_ioctl(struct drm_device *dev, void *data,
			    struct drm_file *file_priv);
int	drm_agp_free_ioctl(struct drm_device *dev, void *data,
			   struct drm_file *file_priv);
int	drm_agp_unbind_ioctl(struct drm_device *dev, void *data,
			     struct drm_file *file_priv);
int	drm_agp_bind_ioctl(struct drm_device *dev, void *data,
			   struct drm_file *file_priv);

				/* Stub support (drm_stub.h) */
extern int drm_setmaster_ioctl(struct drm_device *dev, void *data,
			       struct drm_file *file_priv);
extern int drm_dropmaster_ioctl(struct drm_device *dev, void *data,
				struct drm_file *file_priv);
struct drm_master *drm_master_create(struct drm_minor *minor);
extern struct drm_master *drm_master_get(struct drm_master *master);
extern void drm_master_put(struct drm_master **master);

extern void drm_put_dev(struct drm_device *dev);
extern int drm_put_minor(struct drm_minor **minor);
extern unsigned int drm_debug;
extern unsigned int drm_notyet;

extern unsigned int drm_vblank_offdelay;
extern unsigned int drm_timestamp_precision;
extern unsigned int drm_timestamp_monotonic;

/* Scatter Gather Support (drm_scatter.c) */
int	drm_sg_alloc_ioctl(struct drm_device *dev, void *data,
			   struct drm_file *file_priv);
int	drm_sg_free(struct drm_device *dev, void *data,
		    struct drm_file *file_priv);

/* consistent PCI memory functions (drm_pci.c) */
drm_dma_handle_t *drm_pci_alloc(struct drm_device *dev, size_t size,
				size_t align, dma_addr_t maxaddr);
void	drm_pci_free(struct drm_device *dev, drm_dma_handle_t *dmah);
int	drm_pci_set_busid(struct drm_device *dev, struct drm_master *master);
int	drm_pci_set_unique(struct drm_device *dev, struct drm_master *master,
	    struct drm_unique *u);
int	drm_pci_agp_init(struct drm_device *dev);
int	drm_pci_enable_msi(struct drm_device *dev);
void	drm_pci_disable_msi(struct drm_device *dev);

/* Graphics Execution Manager library functions (drm_gem.c) */
int drm_gem_init(struct drm_device *dev);
void drm_gem_destroy(struct drm_device *dev);

int drm_gem_close_ioctl(struct drm_device *dev, void *data,
			struct drm_file *file_priv);
int drm_gem_flink_ioctl(struct drm_device *dev, void *data,
			struct drm_file *file_priv);
int drm_gem_open_ioctl(struct drm_device *dev, void *data,
		       struct drm_file *file_priv);
int drm_gem_handle_create(struct drm_file *file_priv,
			  struct drm_gem_object *obj,
			  u32 *handlep);
int drm_gem_handle_delete(struct drm_file *file_priv, uint32_t handle);
void drm_gem_object_handle_reference(struct drm_gem_object *obj);
void drm_gem_object_handle_unreference(struct drm_gem_object *obj);
void drm_gem_object_handle_unreference_unlocked(struct drm_gem_object *obj);
void drm_gem_object_handle_free(struct drm_gem_object *obj);
void drm_gem_object_reference(struct drm_gem_object *obj);
void drm_gem_object_unreference(struct drm_gem_object *obj);
void drm_gem_object_unreference_unlocked(struct drm_gem_object *obj);
void drm_gem_object_release(struct drm_gem_object *obj);
void drm_gem_object_free(struct drm_gem_object *obj);
int drm_gem_object_init(struct drm_device *dev, struct drm_gem_object *obj,
    size_t size);
int drm_gem_private_object_init(struct drm_device *dev,
    struct drm_gem_object *obj, size_t size);
struct drm_gem_object *drm_gem_object_alloc(struct drm_device *dev,
    size_t size);
struct drm_gem_object *drm_gem_object_lookup(struct drm_device *dev,
    struct drm_file *file_priv, uint32_t handle);

void drm_gem_open(struct drm_device *dev, struct drm_file *file_priv);
void drm_gem_release(struct drm_device *dev, struct drm_file *file_priv);

int drm_gem_create_mmap_offset(struct drm_gem_object *obj);
void drm_gem_free_mmap_offset(struct drm_gem_object *obj);
int drm_gem_mmap_single(struct drm_device *dev, vm_ooffset_t *offset,
    vm_size_t size, struct vm_object **obj_res, int nprot);
void drm_gem_pager_dtr(void *obj);

struct ttm_bo_device;
int ttm_bo_mmap_single(struct ttm_bo_device *bdev, vm_ooffset_t *offset,
    vm_size_t size, struct vm_object **obj_res, int nprot);
struct ttm_buffer_object;
void ttm_bo_release_mmap(struct ttm_buffer_object *bo);

void drm_device_lock_mtx(struct drm_device *dev);
void drm_device_unlock_mtx(struct drm_device *dev);
int drm_device_sleep_mtx(struct drm_device *dev, void *chan, int flags,
    const char *msg, int timeout);
void drm_device_assert_mtx_locked(struct drm_device *dev);
void drm_device_assert_mtx_unlocked(struct drm_device *dev);

void drm_device_lock_struct(struct drm_device *dev);
void drm_device_unlock_struct(struct drm_device *dev);
int drm_device_sleep_struct(struct drm_device *dev, void *chan, int flags,
    const char *msg, int timeout);
void drm_device_assert_struct_locked(struct drm_device *dev);
void drm_device_assert_struct_unlocked(struct drm_device *dev);

void drm_compat_locking_init(struct drm_device *dev);
void drm_sleep_locking_init(struct drm_device *dev);

/* drm_modes.c */
bool drm_mode_parse_command_line_for_connector(const char *mode_option,
    struct drm_connector *connector, struct drm_cmdline_mode *mode);
struct drm_display_mode *drm_mode_create_from_cmdline_mode(
    struct drm_device *dev, struct drm_cmdline_mode *cmd);

/* drm_edid.c */
u8 *drm_find_cea_extension(struct edid *edid);

/* Inline replacements for drm_alloc and friends */
static __inline__ void *
drm_alloc(size_t size, struct malloc_type *area)
{
	return malloc(size, area, M_NOWAIT);
}

static __inline__ void *
drm_calloc(size_t nmemb, size_t size, struct malloc_type *area)
{
	return malloc(size * nmemb, area, M_NOWAIT | M_ZERO);
}

static __inline__ void *
drm_realloc(void *oldpt, size_t oldsize, size_t size,
    struct malloc_type *area)
{
	return reallocf(oldpt, size, area, M_NOWAIT);
}

static __inline__ void
drm_free(void *pt, size_t size, struct malloc_type *area)
{
	free(pt, area);
}

extern void drm_core_ioremap(struct drm_local_map *map, struct drm_device *dev);
extern void drm_core_ioremap_wc(struct drm_local_map *map, struct drm_device *dev);
extern void drm_core_ioremapfree(struct drm_local_map *map, struct drm_device *dev);

static __inline__ struct drm_local_map * drm_core_findmap(struct drm_device *dev,
							 unsigned int token)
{
	struct drm_map_list *_entry;
	list_for_each_entry(_entry, &dev->maplist, head)
	    if (_entry->user_token == token)
		return _entry->map;
	return NULL;
}

static __inline__ void drm_core_dropmap(struct drm_map *map)
{
}

extern int drm_fill_in_dev(struct drm_device *dev,
			   struct drm_driver *driver);
extern void drm_cancel_fill_in_dev(struct drm_device *dev);
int drm_get_minor(struct drm_device *dev, struct drm_minor **minor, int type);

extern int drm_get_pci_dev(device_t kdev, struct drm_device *dev,
			   struct drm_driver *driver);

#define DRM_PCIE_SPEED_25 1
#define DRM_PCIE_SPEED_50 2
#define DRM_PCIE_SPEED_80 4

extern int drm_pcie_get_speed_cap_mask(struct drm_device *dev, u32 *speed_mask);

#define	drm_can_sleep()	(DRM_HZ & 1)

#endif /* __KERNEL__ */
#endif /* _DRM_P_H_ */
