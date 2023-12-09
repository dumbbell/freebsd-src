/* Public domain. */

/*
 * FreeBSD:
 * <linux/dma-buf-map.h> was renamed to <linux/iosys-map.h> in Linux 5.18. The
 * exported functions and constants were also renamed accordingly.
 *
 * We still have <linux/dma-buf-map.h> to maintain compatibility for all the
 * DRM driver version we support.
 */

#ifndef _LINUX_IOSYS_MAP_H
#define _LINUX_IOSYS_MAP_H

#include <linux/io.h>
#include <linux/string.h>

struct iosys_map {
	union {
		void *vaddr_iomem;
		void *vaddr;
	};
	bool is_iomem;
};

#define	IOSYS_MAP_INIT_VADDR(_vaddr) \
{ \
	.vaddr = (_vaddr), \
	is_iomem = false, \
}

#define	IOSYS_MAP_INIT_OFFSET(map, offset) \
({ \
	struct iosys_map __copy; \
	__copy = *map; \
	iosys_map_incr(&__copy, offset); \
	__copy; \
})

static inline void
iosys_map_incr(struct iosys_map *dbm, size_t n)
{
	if (dbm->is_iomem)
		dbm->vaddr_iomem += n;
	else
		dbm->vaddr += n;
}

#if defined(LINUXKPI_VERSION) && LINUXKPI_VERSION >= 51801
static inline void
iosys_map_memcpy_to(struct iosys_map *dbm, size_t dbm_offset, const void *src,
    size_t len)
{
	if (dbm->is_iomem)
		memcpy_toio(dbm->vaddr_iomem + dbm_offset, src, len);
	else
		memcpy(dbm->vaddr + dbm_offset, src, len);
}
#else
static inline void
iosys_map_memcpy_to(struct iosys_map *dbm, const void *src, size_t len)
{
	if (dbm->is_iomem)
		memcpy_toio(dbm->vaddr_iomem, src, len);
	else
		memcpy(dbm->vaddr, src, len);
}
#endif

static inline void
iosys_map_memcpy_from(void *dbm, const struct iosys_map *src,
    size_t src_offset, size_t len)
{
	if (src->is_iomem)
		memcpy_toio(dbm, src->vaddr_iomem + src_offset, len);
	else
		memcpy(dbm, src->vaddr + src_offset, len);
}

#define	iosys_map_rd(map, offset, type) \
({ \
	type __var; \
	iosys_map_memcpy_from(&__var, map, offset, sizeof(__var)); \
	__var; \
})

#define	iosys_map_wr(map, offset, type, value) \
({ \
	type __var = (value); \
	iosys_map_memcpy_to(map, offset, &__var, sizeof(__var)); \
})

#define	iosys_map_rd_field(map, offset, struct_type, field) \
({ \
	struct_type *__struct; \
	iosys_map_rd(map, \
	    offset + offsetof(struct_type, field), \
	    typeof(__struct->field)); \
})

#define	iosys_map_wr_field(map, offset, struct_type, field, value) \
({ \
	struct_type *__struct; \
	iosys_map_wr(map, \
	    offset + offsetof(struct_type, field), \
	    typeof(__struct->field), \
	    value); \
})

static inline bool
iosys_map_is_null(const struct iosys_map *dbm)
{
	if (dbm->is_iomem)
		return (dbm->vaddr_iomem == NULL);
	else
		return (dbm->vaddr == NULL);
}

static inline bool
iosys_map_is_set(const struct iosys_map *dbm)
{
	if (dbm->is_iomem)
		return (dbm->vaddr_iomem != NULL);
	else
		return (dbm->vaddr != NULL);
}

static inline bool
iosys_map_is_equal(
    const struct iosys_map *dbm_a, const struct iosys_map *dbm_b)
{
	if (dbm_a->is_iomem != dbm_b->is_iomem)
		return (false);

	if (dbm_a->is_iomem)
		return (dbm_a->vaddr_iomem == dbm_b->vaddr_iomem);
	else
		return (dbm_a->vaddr == dbm_b->vaddr);
}

static inline void
iosys_map_clear(struct iosys_map *dbm)
{
	if (dbm->is_iomem) {
		dbm->vaddr_iomem = NULL;
		dbm->is_iomem = false;
	} else {
		dbm->vaddr = NULL;
	}
}

static inline void
iosys_map_set_vaddr_iomem(struct iosys_map *dbm, void *addr)
{
	dbm->vaddr_iomem = addr;
	dbm->is_iomem = true;
}

static inline void
iosys_map_set_vaddr(struct iosys_map *dbm, void *addr)
{
	dbm->vaddr = addr;
	dbm->is_iomem = false;
}

#endif
