/**
 * \file drm_memory.c
 * Memory management wrappers for DRM
 *
 * \author Rickard E. (Rik) Faith <faith@valinux.com>
 * \author Gareth Hughes <gareth@valinux.com>
 */

/*
 * Created: Thu Feb  4 14:00:34 1999 by faith@valinux.com
 *
 * Copyright 1999 Precision Insight, Inc., Cedar Park, Texas.
 * Copyright 2000 VA Linux Systems, Inc., Sunnyvale, California.
 * All Rights Reserved.
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
__FBSDID("$FreeBSD: head/sys/dev/drm2/drm_memory.c 235783 2012-05-22 11:07:44Z kib $");

#include <dev/drm2/drmP.h>

MALLOC_DEFINE(DRM_MEM_DMA, "drm_dma", "DRM DMA Data Structures");
MALLOC_DEFINE(DRM_MEM_SAREA, "drm_sarea", "DRM SAREA Data Structures");
MALLOC_DEFINE(DRM_MEM_DRIVER, "drm_driver", "DRM DRIVER Data Structures");
MALLOC_DEFINE(DRM_MEM_MAGIC, "drm_magic", "DRM MAGIC Data Structures");
MALLOC_DEFINE(DRM_MEM_MINOR, "drm_minor", "DRM MINOR Data Structures");
MALLOC_DEFINE(DRM_MEM_IOCTLS, "drm_ioctls", "DRM IOCTL Data Structures");
MALLOC_DEFINE(DRM_MEM_MAPS, "drm_maps", "DRM MAP Data Structures");
MALLOC_DEFINE(DRM_MEM_BUFS, "drm_bufs", "DRM BUFFER Data Structures");
MALLOC_DEFINE(DRM_MEM_SEGS, "drm_segs", "DRM SEGMENTS Data Structures");
MALLOC_DEFINE(DRM_MEM_PAGES, "drm_pages", "DRM PAGES Data Structures");
MALLOC_DEFINE(DRM_MEM_FILES, "drm_files", "DRM FILE Data Structures");
MALLOC_DEFINE(DRM_MEM_QUEUES, "drm_queues", "DRM QUEUE Data Structures");
MALLOC_DEFINE(DRM_MEM_CMDS, "drm_cmds", "DRM COMMAND Data Structures");
MALLOC_DEFINE(DRM_MEM_MAPPINGS, "drm_mapping", "DRM MAPPING Data Structures");
MALLOC_DEFINE(DRM_MEM_BUFLISTS, "drm_buflists", "DRM BUFLISTS Data Structures");
MALLOC_DEFINE(DRM_MEM_AGPLISTS, "drm_agplists", "DRM AGPLISTS Data Structures");
MALLOC_DEFINE(DRM_MEM_CTXBITMAP, "drm_ctxbitmap",
    "DRM CTXBITMAP Data Structures");
MALLOC_DEFINE(DRM_MEM_SGLISTS, "drm_sglists", "DRM SGLISTS Data Structures");
MALLOC_DEFINE(DRM_MEM_MM, "drm_sman", "DRM MEMORY MANAGER Data Structures");
MALLOC_DEFINE(DRM_MEM_HASHTAB, "drm_hashtab", "DRM HASHTABLE Data Structures");
MALLOC_DEFINE(DRM_MEM_KMS, "drm_kms", "DRM KMS Data Structures");

#if 0 && __OS_HAS_AGP
static void *agp_remap(unsigned long offset, unsigned long size,
		       struct drm_device * dev)
{
	unsigned long i, num_pages =
	    PAGE_ALIGN(size) / PAGE_SIZE;
	struct drm_agp_mem *agpmem;
	struct page **page_map;
	struct page **phys_page_map;
	void *addr;

	size = PAGE_ALIGN(size);

	list_for_each_entry(agpmem, &dev->agp->memory, head)
		if (agpmem->bound <= offset
		    && (agpmem->bound + (agpmem->pages << PAGE_SHIFT)) >=
		    (offset + size))
			break;
	if (&agpmem->head == &dev->agp->memory)
		return NULL;

	/*
	 * OK, we're mapping AGP space on a chipset/platform on which memory accesses by
	 * the CPU do not get remapped by the GART.  We fix this by using the kernel's
	 * page-table instead (that's probably faster anyhow...).
	 */
	/* note: use vmalloc() because num_pages could be large... */
	page_map = vmalloc(num_pages * sizeof(struct page *));
	if (!page_map)
		return NULL;

	phys_page_map = (agpmem->memory->pages + (offset - agpmem->bound) / PAGE_SIZE);
	for (i = 0; i < num_pages; ++i)
		page_map[i] = phys_page_map[i];
	addr = vmap(page_map, num_pages, VM_IOREMAP, PAGE_AGP);
	vfree(page_map);

	return addr;
}

/** Wrapper around agp_free_memory() */
void drm_free_agp(DRM_AGP_MEM * handle, int pages)
{
	agp_free_memory(handle);
}

/** Wrapper around agp_bind_memory() */
int drm_bind_agp(DRM_AGP_MEM * handle, unsigned int start)
{
	return agp_bind_memory(handle, start);
}

/** Wrapper around agp_unbind_memory() */
int drm_unbind_agp(DRM_AGP_MEM * handle)
{
	return agp_unbind_memory(handle);
}

#else  /*  __OS_HAS_AGP  */
static inline void *agp_remap(unsigned long offset, unsigned long size,
			      struct drm_device * dev)
{
	return NULL;
}

#endif				/* agp */

void drm_core_ioremap(struct drm_local_map *map, struct drm_device *dev)
{
#ifdef FREEBSD_NOTYET
	if (drm_core_has_AGP(dev) &&
	    dev->agp && dev->agp->cant_use_aperture && map->type == _DRM_AGP)
		map->handle = agp_remap(map->offset, map->size, dev);
	else
#endif /* FREEBSD_NOTYET */
		map->handle = pmap_mapdev(map->offset, map->size);
}

void drm_core_ioremap_wc(struct drm_local_map *map, struct drm_device *dev)
{
#ifdef FREEBSD_NOTYET
	if (drm_core_has_AGP(dev) &&
	    dev->agp && dev->agp->cant_use_aperture && map->type == _DRM_AGP)
		map->handle = agp_remap(map->offset, map->size, dev);
	else
#endif /* FREEBSD_NOTYET */
		map->handle = pmap_mapdev_attr(map->offset, map->size,
		    VM_MEMATTR_WRITE_COMBINING);
}

void drm_core_ioremapfree(struct drm_local_map *map, struct drm_device *dev)
{
	if (!map->handle || !map->size)
		return;

#ifdef FREEBSD_NOTYET
	if (drm_core_has_AGP(dev) &&
	    dev->agp && dev->agp->cant_use_aperture && map->type == _DRM_AGP)
		vunmap(map->handle);
	else
#endif /* FREEBSD_NOTYET */
		pmap_unmapdev((vm_offset_t)map->handle, map->size);
}

int
drm_mtrr_add(unsigned long offset, size_t size, int flags)
{
	int act;
	struct mem_range_desc mrdesc;

	mrdesc.mr_base = offset;
	mrdesc.mr_len = size;
	mrdesc.mr_flags = flags;
	act = MEMRANGE_SET_UPDATE;
	strlcpy(mrdesc.mr_owner, "drm", sizeof(mrdesc.mr_owner));
	return mem_range_attr_set(&mrdesc, &act);
}

int
drm_mtrr_del(int __unused handle, unsigned long offset, size_t size, int flags)
{
	int act;
	struct mem_range_desc mrdesc;

	mrdesc.mr_base = offset;
	mrdesc.mr_len = size;
	mrdesc.mr_flags = flags;
	act = MEMRANGE_SET_REMOVE;
	strlcpy(mrdesc.mr_owner, "drm", sizeof(mrdesc.mr_owner));
	return mem_range_attr_set(&mrdesc, &act);
}

void
drm_clflush_pages(vm_page_t *pages, unsigned long num_pages)
{

	pmap_invalidate_cache_pages(pages, num_pages);
}
