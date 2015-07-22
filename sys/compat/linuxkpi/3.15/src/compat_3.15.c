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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/sleepqueue.h>

#include <linux/device.h>
#include <linux/kobject.h>
#include <linux/io.h>
#include <linux/pci.h>
#include <linux/vmalloc.h>
#include <linux/netdevice.h>
#include <linux/timer.h>

struct device linuxkpi_rootdev;

unsigned long timer_hz_mask;

#define miscclass LINUXKPI_PREFIXED_SYM(miscclass)
static struct class miscclass;
struct net init_net;

unsigned long timer_hz_mask;

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

struct vmmaphd {
	struct vmmap *lh_first;
};
#define	VMMAP_HASH_SIZE	64
#define	VMMAP_HASH_MASK	(VMMAP_HASH_SIZE - 1)
#define	VM_HASH(addr)	((uintptr_t)(addr) >> PAGE_SHIFT) & VMMAP_HASH_MASK
#define vmmaphead LINUXKPI_PREFIXED_SYM(vmmaphead)
static struct vmmaphd vmmaphead[VMMAP_HASH_SIZE];
#define vmmaplock LINUXKPI_PREFIXED_SYM(vmmaplock)
static struct mtx vmmaplock;

static void
vmmap_add(void *addr, unsigned long size)
{
	struct vmmap *vmmap;

	vmmap = kmalloc(sizeof(*vmmap), GFP_KERNEL);
	mtx_lock(&vmmaplock);
	vmmap->vm_size = size;
	vmmap->vm_addr = addr;
	LIST_INSERT_HEAD(&vmmaphead[VM_HASH(addr)], vmmap, vm_next);
	mtx_unlock(&vmmaplock);
}

static struct vmmap *
vmmap_remove(void *addr)
{
	struct vmmap *vmmap;

	mtx_lock(&vmmaplock);
	LIST_FOREACH(vmmap, &vmmaphead[VM_HASH(addr)], vm_next)
		if (vmmap->vm_addr == addr)
			break;
	if (vmmap)
		LIST_REMOVE(vmmap, vm_next);
	mtx_unlock(&vmmaplock);

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

static int
linux_timer_jiffies_until(unsigned long expires)
{
	int delta = expires - jiffies;
	/* guard against already expired values */
	if (delta < 1)
		delta = 1;
	return (delta);
}

static void
LINUXKPI_PREFIXED_SYM(timer_callback_wrapper)(void *context)
{
	struct timer_list *timer;

	timer = context;
	timer->function(timer->data);
}

void
mod_timer(struct timer_list *timer, unsigned long expires)
{

	timer->expires = expires;
	callout_reset(&timer->timer_callout,
	    linux_timer_jiffies_until(expires),
	    &LINUXKPI_PREFIXED_SYM(timer_callback_wrapper), timer);
}

void
add_timer(struct timer_list *timer)
{

	callout_reset(&timer->timer_callout,
	    linux_timer_jiffies_until(timer->expires),
	    &LINUXKPI_PREFIXED_SYM(timer_callback_wrapper), timer);
}

static void
LINUXKPI_PREFIXED_SYM(timer_init)(void *arg)
{

	/*
	 * Compute an internal HZ value which can divide 2**32 to
	 * avoid timer rounding problems when the tick value wraps
	 * around 2**32:
	 */
	timer_hz_mask = 1;
	while (timer_hz_mask < (unsigned long)hz)
		timer_hz_mask *= 2;
	timer_hz_mask--;
}
SYSINIT(linuxkpi_timer, SI_SUB_DRIVERS, SI_ORDER_FIRST, LINUXKPI_PREFIXED_SYM(timer_init), NULL);

void
complete_common(struct completion *c, int all)
{
	int wakeup_swapper;

	sleepq_lock(c);
	c->done++;
	if (all)
		wakeup_swapper = sleepq_broadcast(c, SLEEPQ_SLEEP, 0, 0);
	else
		wakeup_swapper = sleepq_signal(c, SLEEPQ_SLEEP, 0, 0);
	sleepq_release(c);
	if (wakeup_swapper)
		kick_proc0();
}

/*
 * Indefinite wait for done != 0 with or without signals.
 */
long
wait_for_common(struct completion *c, int flags)
{

	if (flags != 0)
		flags = SLEEPQ_INTERRUPTIBLE | SLEEPQ_SLEEP;
	else
		flags = SLEEPQ_SLEEP;
	for (;;) {
		sleepq_lock(c);
		if (c->done)
			break;
		sleepq_add(c, NULL, "completion", flags, 0);
		if (flags & SLEEPQ_INTERRUPTIBLE) {
			if (sleepq_wait_sig(c, 0) != 0)
				return (-ERESTARTSYS);
		} else
			sleepq_wait(c, 0);
	}
	c->done--;
	sleepq_release(c);

	return (0);
}

/*
 * Time limited wait for done != 0 with or without signals.
 */
long
wait_for_timeout_common(struct completion *c, long timeout, int flags)
{
	long end = jiffies + timeout;

	if (flags != 0)
		flags = SLEEPQ_INTERRUPTIBLE | SLEEPQ_SLEEP;
	else
		flags = SLEEPQ_SLEEP;
	for (;;) {
		int ret;

		sleepq_lock(c);
		if (c->done)
			break;
		sleepq_add(c, NULL, "completion", flags, 0);
		sleepq_set_timeout(c, linux_timer_jiffies_until(end));
		if (flags & SLEEPQ_INTERRUPTIBLE)
			ret = sleepq_timedwait_sig(c, 0);
		else
			ret = sleepq_timedwait(c, 0);
		if (ret != 0) {
			/* check for timeout or signal */
			if (ret == EWOULDBLOCK)
				return (0);
			else
				return (-ERESTARTSYS);
		}
	}
	c->done--;
	sleepq_release(c);

	/* return how many jiffies are left */
	return (linux_timer_jiffies_until(end));
}

int
try_wait_for_completion(struct completion *c)
{
	int isdone;

	isdone = 1;
	sleepq_lock(c);
	if (c->done)
		c->done--;
	else
		isdone = 0;
	sleepq_release(c);
	return (isdone);
}

int
completion_done(struct completion *c)
{
	int isdone;

	isdone = 1;
	sleepq_lock(c);
	if (c->done == 0)
		isdone = 0;
	sleepq_release(c);
	return (isdone);
}

char *
kvasprintf(gfp_t gfp, const char *fmt, va_list ap)
{
	unsigned int len;
	char *p;
	va_list aq;

	va_copy(aq, ap);
	len = vsnprintf(NULL, 0, fmt, aq);
	va_end(aq);

	p = kmalloc(len + 1, gfp);
	if (p != NULL)
		vsnprintf(p, len + 1, fmt, ap);

	return (p);
}

char *
kasprintf(gfp_t gfp, const char *fmt, ...)
{
	va_list ap;
	char *p;

	va_start(ap, fmt);
	p = kvasprintf(gfp, fmt, ap);
	va_end(ap);

	return (p);
}

static void
LINUXKPI_PREFIXED_SYM(compat_init)(void *arg)
{
	struct sysctl_oid *rootoid;
	int i;

	rootoid = SYSCTL_ADD_ROOT_NODE(NULL,
	    OID_AUTO, "sys", CTLFLAG_RD|CTLFLAG_MPSAFE, NULL, "sys");
	kobject_init(&class_root, &class_ktype);
	kobject_set_name(&class_root, "class");
	class_root.oidp = SYSCTL_ADD_NODE(NULL, SYSCTL_CHILDREN(rootoid),
	    OID_AUTO, "class", CTLFLAG_RD|CTLFLAG_MPSAFE, NULL, "class");
	kobject_init(&linuxkpi_rootdev.kobj, &dev_ktype);
	kobject_set_name(&linuxkpi_rootdev.kobj, "device");
	linuxkpi_rootdev.kobj.oidp = SYSCTL_ADD_NODE(NULL,
	    SYSCTL_CHILDREN(rootoid), OID_AUTO, "device", CTLFLAG_RD, NULL,
	    "device");
	linuxkpi_rootdev.bsddev = root_bus;
	miscclass.name = "misc";
	class_register(&miscclass);
	INIT_LIST_HEAD(&pci_drivers);
	INIT_LIST_HEAD(&pci_devices);
	spin_lock_init(&pci_lock);
	mtx_init(&vmmaplock, "IO Map lock", NULL, MTX_DEF);
	for (i = 0; i < VMMAP_HASH_SIZE; i++)
		LIST_INIT(&vmmaphead[i]);
}
SYSINIT(linuxkpi_compat, SI_SUB_DRIVERS, SI_ORDER_SECOND,
    LINUXKPI_PREFIXED_SYM(compat_init), NULL);

static void
LINUXKPI_PREFIXED_SYM(compat_uninit)(void *arg)
{
	kobject_kfree_name(&class_root);
	kobject_kfree_name(&linuxkpi_rootdev.kobj);
	kobject_kfree_name(&miscclass.kobj);
}

SYSUNINIT(linuxkpi_compat, SI_SUB_DRIVERS, SI_ORDER_SECOND,
    LINUXKPI_PREFIXED_SYM(compat_uninit), NULL);
