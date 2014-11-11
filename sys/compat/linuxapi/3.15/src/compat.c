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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <linux/device.h>
#include <linux/kobject.h>
#include <linux/io.h>
#include <linux/vmalloc.h>

/* From sys/queue.h */
#undef LIST_HEAD
#define LIST_HEAD(name, type)						\
struct name {								\
	struct type *lh_first;	/* first element */			\
}

struct device LINUXAPI_PREFIXED_SYM(linux_rootdev);

static struct class LINUXAPI_PREFIXED_SYM(miscclass);
static struct list_head LINUXAPI_PREFIXED_SYM(pci_drivers);
static struct list_head LINUXAPI_PREFIXED_SYM(pci_devices);
static spinlock_t LINUXAPI_PREFIXED_SYM(pci_lock);

/*
 * Hash of vmmap addresses.  This is infrequently accessed and does not
 * need to be particularly large.  This is done because we must store the
 * caller's idea of the map size to properly unmap.
 */
struct vmmap {
	LIST_ENTRY(vmmap)	vm_next;
	void 			*vm_addr;
	unsigned long		vm_size;
};

LIST_HEAD(vmmaphd, vmmap);
#define	VMMAP_HASH_SIZE	64
#define	VMMAP_HASH_MASK	(VMMAP_HASH_SIZE - 1)
#define	VM_HASH(addr)	((uintptr_t)(addr) >> PAGE_SHIFT) & VMMAP_HASH_MASK
static struct vmmaphd LINUXAPI_PREFIXED_SYM(vmmaphead)[VMMAP_HASH_SIZE];
static struct mtx LINUXAPI_PREFIXED_SYM(vmmaplock);

static void
vmmap_add(void *addr, unsigned long size)
{
	struct vmmap *vmmap;

	vmmap = kmalloc(sizeof(*vmmap), GFP_KERNEL);
	mtx_lock(&LINUXAPI_PREFIXED_SYM(vmmaplock));
	vmmap->vm_size = size;
	vmmap->vm_addr = addr;
	LIST_INSERT_HEAD(&LINUXAPI_PREFIXED_SYM(vmmaphead)[VM_HASH(addr)],
	    vmmap, vm_next);
	mtx_unlock(&LINUXAPI_PREFIXED_SYM(vmmaplock));
}

static struct vmmap *
vmmap_remove(void *addr)
{
	struct vmmap *vmmap;

	mtx_lock(&LINUXAPI_PREFIXED_SYM(vmmaplock));
	LIST_FOREACH(vmmap, &LINUXAPI_PREFIXED_SYM(vmmaphead)[VM_HASH(addr)], vm_next)
		if (vmmap->vm_addr == addr)
			break;
	if (vmmap)
		LIST_REMOVE(vmmap, vm_next);
	mtx_unlock(&LINUXAPI_PREFIXED_SYM(vmmaplock));

	return (vmmap);
}


void *
vmap(struct page **pages, unsigned int count, unsigned long flags, int prot)
{
	vm_offset_t off;
	size_t size;

	size = count * PAGE_SIZE;
	off = kva_alloc(size);
	if (off == 0)
		return (NULL);
	vmmap_add((void *)off, size);
	pmap_qenter(off, pages, count);

	return ((void *)off);
}

void
vunmap(void *addr)
{
	struct vmmap *vmmap;

	vmmap = vmmap_remove(addr);
	if (vmmap == NULL)
		return;
	pmap_qremove((vm_offset_t)addr, vmmap->vm_size / PAGE_SIZE);
	kva_free((vm_offset_t)addr, vmmap->vm_size);
	kfree(vmmap);
}

void *
_ioremap_attr(vm_paddr_t phys_addr, unsigned long size, int attr)
{
	void *addr;

	addr = pmap_mapdev_attr(phys_addr, size, attr);
	if (addr == NULL)
		return (NULL);
	vmmap_add(addr, size);

	return (addr);
}

void
iounmap(void *addr)
{
	struct vmmap *vmmap;

	vmmap = vmmap_remove(addr);
	if (vmmap == NULL)
		return;
	pmap_unmapdev((vm_offset_t)addr, vmmap->vm_size);
	kfree(vmmap);
}

static void
LINUXAPI_PREFIXED_SYM(compat_init)(void)
{
	struct sysctl_oid *rootoid;
	int i;

	rootoid = SYSCTL_ADD_ROOT_NODE(NULL,
	    OID_AUTO, "sys", CTLFLAG_RD|CTLFLAG_MPSAFE, NULL, "sys");
	kobject_init(&LINUXAPI_PREFIXED_SYM(class_root),
	    &LINUXAPI_PREFIXED_SYM(class_ktype));
	kobject_set_name(&LINUXAPI_PREFIXED_SYM(class_root), "class");
	LINUXAPI_PREFIXED_SYM(class_root).oidp = SYSCTL_ADD_NODE(NULL,
	    SYSCTL_CHILDREN(rootoid),
	    OID_AUTO, "class", CTLFLAG_RD|CTLFLAG_MPSAFE, NULL, "class");
	kobject_init(&LINUXAPI_PREFIXED_SYM(linux_rootdev).kobj,
	    &LINUXAPI_PREFIXED_SYM(dev_ktype));
	kobject_set_name(&LINUXAPI_PREFIXED_SYM(linux_rootdev).kobj, "device");
	LINUXAPI_PREFIXED_SYM(linux_rootdev).kobj.oidp = SYSCTL_ADD_NODE(NULL,
	    SYSCTL_CHILDREN(rootoid), OID_AUTO, "device", CTLFLAG_RD, NULL,
	    "device");
	LINUXAPI_PREFIXED_SYM(linux_rootdev).bsddev = root_bus;
	LINUXAPI_PREFIXED_SYM(miscclass).name = "misc";
	class_register(&LINUXAPI_PREFIXED_SYM(miscclass));
	INIT_LIST_HEAD(&LINUXAPI_PREFIXED_SYM(pci_drivers));
	INIT_LIST_HEAD(&LINUXAPI_PREFIXED_SYM(pci_devices));
	spin_lock_init(&LINUXAPI_PREFIXED_SYM(pci_lock));
	mtx_init(&LINUXAPI_PREFIXED_SYM(vmmaplock), "IO Map lock", NULL, MTX_DEF);
	for (i = 0; i < VMMAP_HASH_SIZE; i++)
		LIST_INIT(&LINUXAPI_PREFIXED_SYM(vmmaphead)[i]);
}

SYSINIT(linuxapi_compat, SI_SUB_DRIVERS, SI_ORDER_SECOND,
    LINUXAPI_PREFIXED_SYM(compat_init), NULL);

static void
LINUXAPI_PREFIXED_SYM(compat_uninit)(void)
{
	kobject_kfree_name(&LINUXAPI_PREFIXED_SYM(class_root));
	kobject_kfree_name(&LINUXAPI_PREFIXED_SYM(linux_rootdev).kobj);
	kobject_kfree_name(&LINUXAPI_PREFIXED_SYM(miscclass.kobj));
}

SYSUNINIT(linuxapi_compat, SI_SUB_DRIVERS, SI_ORDER_SECOND,
    LINUXAPI_PREFIXED_SYM(compat_uninit), NULL);
