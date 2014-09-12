/*-
 * Copyright (c) 2010 Isilon Systems, Inc.
 * Copyright (c) 2010 iX Systems, Inc.
 * Copyright (c) 2010 Panasas, Inc.
 * Copyright (c) 2013, 2014 Mellanox Technologies, Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef USERLAND_TEST

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/lock.h>
#include <sys/mutex.h>

#include <machine/stdarg.h>

#include <dev/drm2/drm_idr.h>

#include <../../ofed/include/linux/bitops.h>
#include <../../ofed/include/linux/err.h>

static MALLOC_DEFINE(M_DRM_IDR, "idr", "Linux IDR compat");

#else /* defined(USERLAND_TEST) */

struct mtx {
};

#include <sys/param.h>
#include <sys/queue.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

typedef	unsigned int	gfp_t;

#define	malloc(s, m, f)	calloc(1, (s))
#define	malloc(s, m, f)	calloc(1, (s))
#define	free(p, m)	free(p)

#define	mtx_lock(p)
#define	mtx_unlock(p)
#define	mtx_init(p, s, a, f)

#define	panic	printf

#define min(x, y)	((x) < (y) ? (x) : (y))
#define max(x, y)	((x) > (y) ? (x) : (y))

static int
atomic_cmpset_long(long *dst, long old, long new)
{

	if (*dst == old) {
		*dst = new;
		return (1);
	} else
		return (0);
}

#include <linux/bitops.h>
#include <linux/err.h>
#include <linux/idr.h>

#endif

/*
 * IDR Implementation.
 *
 * This is quick and dirty and not as re-entrant as the linux version
 * however it should be fairly fast.  It is basically a radix tree with
 * a builtin bitmap for allocation.
 */

static inline int
idr_max(struct idr *idr)
{
	return (1 << (idr->layers * IDR_BITS)) - 1;
}

static inline int
idr_pos(int id, int layer)
{
	return (id >> (IDR_BITS * layer)) & IDR_MASK;
}

void
idr_init(struct idr *idr)
{
	bzero(idr, sizeof(*idr));
	mtx_init(&idr->lock, "idr", NULL, MTX_DEF);
}

/* Only frees cached pages. */
void
idr_destroy(struct idr *idr)
{
	struct idr_layer *il, *iln;

	mtx_lock(&idr->lock);
	for (il = idr->free; il != NULL; il = iln) {
		iln = il->ary[0];
		free(il, M_DRM_IDR);
	}
	mtx_unlock(&idr->lock);
}

static void
idr_remove_layer(struct idr_layer *il, int layer)
{
	int i;

	if (il == NULL)
		return;
	if (layer == 0) {
		free(il, M_DRM_IDR);
		return;
	}
	for (i = 0; i < IDR_SIZE; i++)
		if (il->ary[i])
			idr_remove_layer(il->ary[i], layer - 1);
}

void
idr_remove_all(struct idr *idr)
{

	mtx_lock(&idr->lock);
	idr_remove_layer(idr->top, idr->layers - 1);
	idr->top = NULL;
	idr->layers = 0;
	mtx_unlock(&idr->lock);
}

void
idr_remove(struct idr *idr, int id)
{
	struct idr_layer *il;
	int layer;
	int idx;

	id &= MAX_ID_MASK;
	mtx_lock(&idr->lock);
	il = idr->top;
	layer = idr->layers - 1;
	if (il == NULL || id > idr_max(idr)) {
		mtx_unlock(&idr->lock);
		return;
	}
	/*
	 * Walk down the tree to this item setting bitmaps along the way
	 * as we know at least one item will be free along this path.
	 */
	while (layer && il) {
		idx = idr_pos(id, layer);
		il->bitmap |= 1 << idx;
		il = il->ary[idx];
		layer--;
	}
	idx = id & IDR_MASK;
	/*
	 * At this point we've set free space bitmaps up the whole tree.
	 * We could make this non-fatal and unwind but linux dumps a stack
	 * and a warning so I don't think it's necessary.
	 */
	if (il == NULL || (il->bitmap & (1 << idx)) != 0)
		panic("idr_remove: Item %d not allocated (%p, %p)\n",
		    id, idr, il);
	il->ary[idx] = NULL;
	il->bitmap |= 1 << idx;
	mtx_unlock(&idr->lock);
	return;
}

void *
idr_replace(struct idr *idr, void *ptr, int id)
{
	struct idr_layer *il;
	void *res;
	int layer;
	int idx;

	res = ERR_PTR(-EINVAL);
	id &= MAX_ID_MASK;
	mtx_lock(&idr->lock);
	il = idr->top;
	layer = idr->layers - 1;
	if (il == NULL || id > idr_max(idr))
		goto out;
	while (layer && il) {
		il = il->ary[idr_pos(id, layer)];
		layer--;
	}
	idx = id & IDR_MASK;
	/*
	 * Replace still returns an error if the item was not allocated.
	 */
	if (il != NULL && (il->bitmap & (1 << idx)) != 0) {
		res = il->ary[idx];
		il->ary[idx] = ptr;
	}
out:
	mtx_unlock(&idr->lock);
	return (res);
}

void *
idr_find(struct idr *idr, int id)
{
	struct idr_layer *il;
	void *res;
	int layer;

	res = NULL;
	id &= MAX_ID_MASK;
	mtx_lock(&idr->lock);
	il = idr->top;
	layer = idr->layers - 1;
	if (il == NULL || id > idr_max(idr))
		goto out;
	while (layer && il) {
		il = il->ary[idr_pos(id, layer)];
		layer--;
	}
	if (il != NULL)
		res = il->ary[id & IDR_MASK];
out:
	mtx_unlock(&idr->lock);
	return (res);
}

static int
idr_for_each_layer(struct idr_layer *il, int layer, int id,
    int (*fn)(int id, void *p, void *data), void *data)
{
	int idx, ret, sub_id;

	if (il == NULL)
		return (0);

	for (idx = 0; idx < IDR_SIZE; ++idx) {
		if (il->ary[idx] == NULL)
			continue;

		sub_id = id | idx << (layer * IDR_BITS);

		if (layer > 0)
			ret = idr_for_each_layer(il->ary[idx], layer - 1, sub_id,
			    fn, data);
		else
			ret = fn(sub_id, il->ary[idx], data);

		if (ret != 0)
			return (ret);
	}

	return (0);
}

int
idr_for_each(struct idr *idr,
    int (*fn)(int id, void *p, void *data), void *data)
{
	int ret;

	ret = idr_for_each_layer(idr->top, idr->layers - 1, 0, fn, data);

	return (ret);
}

int
idr_pre_get(struct idr *idr, gfp_t gfp_mask)
{
	struct idr_layer *il, *iln;
	struct idr_layer *head;
	int need;

	mtx_lock(&idr->lock);
	for (;;) {
		need = idr->layers + 1;
		for (il = idr->free; il != NULL; il = il->ary[0])
			need--;
		mtx_unlock(&idr->lock);
		if (need == 0)
			break;
		for (head = NULL; need; need--) {
			iln = malloc(sizeof(*il), M_DRM_IDR, M_ZERO | M_NOWAIT);
			if (iln == NULL)
				break;
			bitmap_fill(&iln->bitmap, IDR_SIZE);
			if (head != NULL) {
				il->ary[0] = iln;
				il = iln;
			} else
				head = il = iln;
		}
		if (head == NULL)
			return (0);
		mtx_lock(&idr->lock);
		il->ary[0] = idr->free;
		idr->free = head;
	}
	return (1);
}

static inline struct idr_layer *
idr_get(struct idr *idr)
{
	struct idr_layer *il;

	il = idr->free;
	if (il) {
		idr->free = il->ary[0];
		il->ary[0] = NULL;
		return (il);
	}
	il = malloc(sizeof(*il), M_DRM_IDR, M_ZERO | M_NOWAIT);
	bitmap_fill(&il->bitmap, IDR_SIZE);
	return (il);
}

/*
 * Could be implemented as get_new_above(idr, ptr, 0, idp) but written
 * first for simplicity sake.
 */
int
idr_get_new(struct idr *idr, void *ptr, int *idp)
{
	struct idr_layer *stack[MAX_LEVEL];
	struct idr_layer *il;
	int error;
	int layer;
	int idx;
	int id;

	error = -EAGAIN;
	mtx_lock(&idr->lock);
	/*
	 * Expand the tree until there is free space.
	 */
	if (idr->top == NULL || idr->top->bitmap == 0) {
		if (idr->layers == MAX_LEVEL + 1) {
			error = -ENOSPC;
			goto out;
		}
		il = idr_get(idr);
		if (il == NULL)
			goto out;
		il->ary[0] = idr->top;
		if (idr->top)
			il->bitmap &= ~1;
		idr->top = il;
		idr->layers++;
	}
	il = idr->top;
	id = 0;
	/*
	 * Walk the tree following free bitmaps, record our path.
	 */
	for (layer = idr->layers - 1;; layer--) {
		stack[layer] = il;
		idx = ffsl(il->bitmap);
		if (idx == 0)
			panic("idr_get_new: Invalid leaf state (%p, %p)\n",
			    idr, il);
		idx--;
		id |= idx << (layer * IDR_BITS);
		if (layer == 0)
			break;
		if (il->ary[idx] == NULL) {
			il->ary[idx] = idr_get(idr);
			if (il->ary[idx] == NULL)
				goto out;
		}
		il = il->ary[idx];
	}
	/*
	 * Allocate the leaf to the consumer.
	 */
	il->bitmap &= ~(1 << idx);
	il->ary[idx] = ptr;
	*idp = id;
	/*
	 * Clear bitmaps potentially up to the root.
	 */
	while (il->bitmap == 0 && ++layer < idr->layers) {
		il = stack[layer];
		il->bitmap &= ~(1 << idr_pos(id, layer));
	}
	error = 0;
out:
	mtx_unlock(&idr->lock);
#ifdef INVARIANTS
	if (error == 0 && idr_find(idr, id) != ptr) {
		panic("idr_get_new: Failed for idr %p, id %d, ptr %p\n",
		    idr, id, ptr);
	}
#endif
	return (error);
}

int
idr_get_new_above(struct idr *idr, void *ptr, int starting_id, int *idp)
{
	struct idr_layer *stack[MAX_LEVEL];
	struct idr_layer *il;
	int error;
	int layer;
	int idx, sidx;
	int id;

	error = -EAGAIN;
	mtx_lock(&idr->lock);
	/*
	 * Compute the layers required to support starting_id and the mask
	 * at the top layer.
	 */
restart:
	idx = starting_id;
	layer = 0;
	while (idx & ~IDR_MASK) {
		layer++;
		idx >>= IDR_BITS;
	}
	if (layer == MAX_LEVEL + 1) {
		error = -ENOSPC;
		goto out;
	}
	/*
	 * Expand the tree until there is free space at or beyond starting_id.
	 */
	while (idr->layers <= layer ||
	    idr->top->bitmap < (1 << idr_pos(starting_id, idr->layers - 1))) {
		if (idr->layers == MAX_LEVEL + 1) {
			error = -ENOSPC;
			goto out;
		}
		il = idr_get(idr);
		if (il == NULL)
			goto out;
		il->ary[0] = idr->top;
		if (idr->top && idr->top->bitmap == 0)
			il->bitmap &= ~1;
		idr->top = il;
		idr->layers++;
	}
	il = idr->top;
	id = 0;
	/*
	 * Walk the tree following free bitmaps, record our path.
	 */
	for (layer = idr->layers - 1;; layer--) {
		stack[layer] = il;
		sidx = idr_pos(starting_id, layer);
		/* Returns index numbered from 0 or size if none exists. */
		idx = find_next_bit(&il->bitmap, IDR_SIZE, sidx);
		if (idx == IDR_SIZE && sidx == 0)
			panic("idr_get_new: Invalid leaf state (%p, %p)\n",
			    idr, il);
		/*
		 * We may have walked a path where there was a free bit but
		 * it was lower than what we wanted.  Restart the search with
		 * a larger starting id.  id contains the progress we made so
		 * far.  Search the leaf one above this level.  This may
		 * restart as many as MAX_LEVEL times but that is expected
		 * to be rare.
		 */
		if (idx == IDR_SIZE) {
			starting_id = id + (1 << (layer+1 * IDR_BITS));
			goto restart;
		}
		if (idx > sidx)
			starting_id = 0;	/* Search the whole subtree. */
		id |= idx << (layer * IDR_BITS);
		if (layer == 0)
			break;
		if (il->ary[idx] == NULL) {
			il->ary[idx] = idr_get(idr);
			if (il->ary[idx] == NULL)
				goto out;
		}
		il = il->ary[idx];
	}
	/*
	 * Allocate the leaf to the consumer.
	 */
	il->bitmap &= ~(1 << idx);
	il->ary[idx] = ptr;
	*idp = id;
	/*
	 * Clear bitmaps potentially up to the root.
	 */
	while (il->bitmap == 0 && ++layer < idr->layers) {
		il = stack[layer];
		il->bitmap &= ~(1 << idr_pos(id, layer));
	}
	error = 0;
out:
	mtx_unlock(&idr->lock);
#ifdef INVARIANTS
	if (error == 0 && idr_find(idr, id) != ptr) {
		panic("idr_get_new_above: Failed for idr %p, id %d, ptr %p\n",
		    idr, id, ptr);
	}
#endif
	return (error);
}

#ifdef USERLAND_TEST
static int
foreach_fn(int id, void *res, void *data)
{

	printf("%s: id=%d, value=%08x\n\n", (char *)data, id, (int)res);

	return (0);
}

int
main(int argc, char *argv[])
{
	char buf[256];
	struct idr idr;
	intptr_t generation = 0x10000000;
	int error;
	int id;

	idr_init(&idr);

	printf("cmd> ");
	fflush(stdout);
	while (fgets(buf, sizeof(buf), stdin) != NULL) {
		if (sscanf(buf, "a %d", &id) == 1) {
			for (;;) {
				if (idr_pre_get(&idr, 0) == 0) {
					fprintf(stderr, "pre_get failed\n");
					exit(1);
				}
				error = idr_get_new_above(&idr,
							  (void *)generation,
							  id, &id);
				if (error == -EAGAIN)
					continue;
				if (error) {
					fprintf(stderr, "get_new err %d\n",
						error);
					exit(1);
				}
				printf("allocated %d value %08x\n",
					id, (int)generation);
				++generation;
				break;
			}
		} else if (strcmp(buf, "l\n") == 0) {
			printf("Entries:\n");
			idr_for_each(&idr, foreach_fn, "Entry");
		} else if (sscanf(buf, "r %d", &id) == 1) {
			idr_remove(&idr, id);
		} else if (sscanf(buf, "f %d", &id) == 1) {
			void *res = idr_find(&idr, id);
			printf("find %d res %p\n", id, res);
		}
		printf("cmd> ");
		fflush(stdout);
	}

	//idr_destroy(&idr);

	return 0;
}
#endif
