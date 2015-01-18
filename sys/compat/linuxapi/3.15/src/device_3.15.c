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
#include <sys/filio.h>
#include <sys/fcntl.h>
#include <sys/lock.h>
#include <sys/rwlock.h>

#include <vm/vm.h>
#include <vm/vm_object.h>

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/file.h>
#include <linux/kobject.h>
#include <linux/mm.h>

#include <vm/vm_pager.h>

/* Undo Linux compat changes. */
#undef file
#undef cdev

struct kobject class_root;

ssize_t
show_class_attr_string(struct class *class,
    struct class_attribute *attr, char *buf)
{
	struct class_attribute_string *cs;
	cs = container_of(attr, struct class_attribute_string, attr);
	return snprintf(buf, PAGE_SIZE, "%s\n", cs->str);
}

static ssize_t
LINUXAPI_PREFIXED_SYM(class_show)(struct kobject *kobj, struct attribute *attr, char *buf)
{
	struct class_attribute *dattr;
	ssize_t error;

	dattr = container_of(attr, struct class_attribute, attr);
	error = -EIO;
	if (dattr->show)
		error = dattr->show(container_of(kobj, struct class, kobj),
		    dattr, buf);
	return (error);
}

static ssize_t
LINUXAPI_PREFIXED_SYM(class_store)(struct kobject *kobj, struct attribute *attr, const char *buf,
    size_t count)
{
	struct class_attribute *dattr;
	ssize_t error;

	dattr = container_of(attr, struct class_attribute, attr);
	error = -EIO;
	if (dattr->store)
		error = dattr->store(container_of(kobj, struct class, kobj),
		    dattr, buf, count);
	return (error);
}

static void
LINUXAPI_PREFIXED_SYM(class_release)(struct kobject *kobj)
{
	struct class *class;

	class = container_of(kobj, struct class, kobj);
	if (class->class_release)
		class->class_release(class);
}

static struct sysfs_ops LINUXAPI_PREFIXED_SYM(class_sysfs) = {
	.show  = LINUXAPI_PREFIXED_SYM(class_show),
	.store = LINUXAPI_PREFIXED_SYM(class_store),
};
struct kobj_type class_ktype = {
	.release = LINUXAPI_PREFIXED_SYM(class_release),
	.sysfs_ops = &LINUXAPI_PREFIXED_SYM(class_sysfs)
};

int
class_register(struct class *class)
{

	class->bsdclass = devclass_create(class->name);
	kobject_init(&class->kobj, &class_ktype);
	kobject_set_name(&class->kobj, class->name);
	kobject_add(&class->kobj, &class_root, class->name);

	return (0);
}

void
class_unregister(struct class *class)
{

	kobject_put(&class->kobj);
}

static void
LINUXAPI_PREFIXED_SYM(class_kfree)(struct class *class)
{

	kfree(class);
}

struct class *
class_create(struct module *owner, const char *name)
{
	struct class *class;
	int error;

	class = kzalloc(sizeof(*class), M_WAITOK);
	class->owner = owner;
	class->name= name;
	class->class_release = LINUXAPI_PREFIXED_SYM(class_kfree);
	error = class_register(class);
	if (error) {
		kfree(class);
		return (NULL);
	}

	return (class);
}

void
class_destroy(struct class *class)
{

	if (class == NULL)
		return;
	class_unregister(class);
}

int
class_create_file(struct class *class, const struct class_attribute *attr)
{

	if (class)
		return sysfs_create_file(&class->kobj, &attr->attr);
	return -EINVAL;
}

void
class_remove_file(struct class *class, const struct class_attribute *attr)
{

	if (class)
		sysfs_remove_file(&class->kobj, &attr->attr);
}

static void
LINUXAPI_PREFIXED_SYM(file_dtor)(void *cdp)
{
	struct linux_file *filp;

	filp = cdp;
	filp->f_op->release(filp->f_vnode, filp);
	vdrop(filp->f_vnode);
	kfree(filp);
}

static int
LINUXAPI_PREFIXED_SYM(dev_open)(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
	struct linux_cdev *ldev;
	struct linux_file *filp;
	struct file *file;
	int error;

	file = curthread->td_fpop;
	ldev = dev->si_drv1;
	if (ldev == NULL)
		return (ENODEV);
	filp = kzalloc(sizeof(*filp), GFP_KERNEL);
	filp->f_dentry = &filp->f_dentry_store;
	filp->f_op = ldev->ops;
	filp->f_flags = file->f_flag;
	vhold(file->f_vnode);
	filp->f_vnode = file->f_vnode;
	if (filp->f_op->open) {
		error = -filp->f_op->open(file->f_vnode, filp);
		if (error) {
			kfree(filp);
			return (error);
		}
	}
	error = devfs_set_cdevpriv(filp, LINUXAPI_PREFIXED_SYM(file_dtor));
	if (error) {
		filp->f_op->release(file->f_vnode, filp);
		kfree(filp);
		return (error);
	}

	return 0;
}

static int
LINUXAPI_PREFIXED_SYM(dev_close)(struct cdev *dev, int fflag, int devtype, struct thread *td)
{
	struct linux_cdev *ldev;
	struct linux_file *filp;
	struct file *file;
	int error;

	file = curthread->td_fpop;
	ldev = dev->si_drv1;
	if (ldev == NULL)
		return (0);
	if ((error = devfs_get_cdevpriv((void **)&filp)) != 0)
		return (error);
	filp->f_flags = file->f_flag;
        devfs_clear_cdevpriv();
        

	return (0);
}

static int
LINUXAPI_PREFIXED_SYM(dev_ioctl)(struct cdev *dev, u_long cmd, caddr_t data, int fflag,
    struct thread *td)
{
	struct linux_cdev *ldev;
	struct linux_file *filp;
	struct file *file;
	int error;

	file = curthread->td_fpop;
	ldev = dev->si_drv1;
	if (ldev == NULL)
		return (0);
	if ((error = devfs_get_cdevpriv((void **)&filp)) != 0)
		return (error);
	filp->f_flags = file->f_flag;
	/*
	 * Linux does not have a generic ioctl copyin/copyout layer.  All
	 * linux ioctls must be converted to void ioctls which pass a
	 * pointer to the address of the data.  We want the actual user
	 * address so we dereference here.
	 */
	data = *(void **)data;
	if (filp->f_op->unlocked_ioctl)
		error = -filp->f_op->unlocked_ioctl(filp, cmd, (u_long)data);
	else
		error = ENOTTY;

	return (error);
}

static int
LINUXAPI_PREFIXED_SYM(dev_read)(struct cdev *dev, struct uio *uio, int ioflag)
{
	struct linux_cdev *ldev;
	struct linux_file *filp;
	struct file *file;
	ssize_t bytes;
	int error;

	file = curthread->td_fpop;
	ldev = dev->si_drv1;
	if (ldev == NULL)
		return (0);
	if ((error = devfs_get_cdevpriv((void **)&filp)) != 0)
		return (error);
	filp->f_flags = file->f_flag;
	if (uio->uio_iovcnt != 1)
		panic("linux_dev_read: uio %p iovcnt %d",
		    uio, uio->uio_iovcnt);
	if (filp->f_op->read) {
		bytes = filp->f_op->read(filp, uio->uio_iov->iov_base,
		    uio->uio_iov->iov_len, &uio->uio_offset);
		if (bytes >= 0) {
			uio->uio_iov->iov_base =
			    ((uint8_t *)uio->uio_iov->iov_base) + bytes;
			uio->uio_iov->iov_len -= bytes;
			uio->uio_resid -= bytes;
		} else
			error = -bytes;
	} else
		error = ENXIO;

	return (error);
}

static int
LINUXAPI_PREFIXED_SYM(dev_write)(struct cdev *dev, struct uio *uio, int ioflag)
{
	struct linux_cdev *ldev;
	struct linux_file *filp;
	struct file *file;
	ssize_t bytes;
	int error;

	file = curthread->td_fpop;
	ldev = dev->si_drv1;
	if (ldev == NULL)
		return (0);
	if ((error = devfs_get_cdevpriv((void **)&filp)) != 0)
		return (error);
	filp->f_flags = file->f_flag;
	if (uio->uio_iovcnt != 1)
		panic("linux_dev_write: uio %p iovcnt %d",
		    uio, uio->uio_iovcnt);
	if (filp->f_op->write) {
		bytes = filp->f_op->write(filp, uio->uio_iov->iov_base,
		    uio->uio_iov->iov_len, &uio->uio_offset);
		if (bytes >= 0) {
			uio->uio_iov->iov_base =
			    ((uint8_t *)uio->uio_iov->iov_base) + bytes;
			uio->uio_iov->iov_len -= bytes;
			uio->uio_resid -= bytes;
		} else
			error = -bytes;
	} else
		error = ENXIO;

	return (error);
}

static int
LINUXAPI_PREFIXED_SYM(dev_poll)(struct cdev *dev, int events, struct thread *td)
{
	struct linux_cdev *ldev;
	struct linux_file *filp;
	struct file *file;
	int revents;
	int error;

	file = curthread->td_fpop;
	ldev = dev->si_drv1;
	if (ldev == NULL)
		return (0);
	if ((error = devfs_get_cdevpriv((void **)&filp)) != 0)
		return (error);
	filp->f_flags = file->f_flag;
	if (filp->f_op->poll)
		revents = filp->f_op->poll(filp, NULL) & events;
	else
		revents = 0;

	return (revents);
}

static int
LINUXAPI_PREFIXED_SYM(dev_mmap)(struct cdev *dev, vm_ooffset_t offset, vm_paddr_t *paddr,
    int nprot, vm_memattr_t *memattr)
{

	/* XXX memattr not honored. */
	*paddr = offset;
	return (0);
}

static int
LINUXAPI_PREFIXED_SYM(dev_mmap_single)(struct cdev *dev, vm_ooffset_t *offset,
    vm_size_t size, struct vm_object **object, int nprot)
{
	struct linux_cdev *ldev;
	struct linux_file *filp;
	struct file *file;
	struct vm_area_struct vma;
	vm_paddr_t paddr;
	vm_page_t m;
	int error;

	file = curthread->td_fpop;
	ldev = dev->si_drv1;
	if (ldev == NULL)
		return (ENODEV);
	if (size != PAGE_SIZE)
		return (EINVAL);
	if ((error = devfs_get_cdevpriv((void **)&filp)) != 0)
		return (error);
	filp->f_flags = file->f_flag;
	vma.vm_start = 0;
	vma.vm_end = PAGE_SIZE;
	vma.vm_pgoff = *offset / PAGE_SIZE;
	vma.vm_pfn = 0;
	vma.vm_page_prot = 0;
	if (filp->f_op->mmap) {
		error = -filp->f_op->mmap(filp, &vma);
		if (error == 0) {
			paddr = (vm_paddr_t)vma.vm_pfn << PAGE_SHIFT;
			*offset = paddr;
			m = PHYS_TO_VM_PAGE(paddr);
			*object = vm_pager_allocate(OBJT_DEVICE, dev,
			    PAGE_SIZE, nprot, *offset, curthread->td_ucred);
		        if (*object == NULL)
               			 return (EINVAL);
			if (vma.vm_page_prot != VM_MEMATTR_DEFAULT)
				pmap_page_set_memattr(m, vma.vm_page_prot);
		}
	} else
		error = ENODEV;

	return (error);
}

struct cdevsw LINUXAPI_PREFIXED_SYM(linuxcdevsw) = {
	.d_version = D_VERSION,
	.d_flags = D_TRACKCLOSE,
	.d_open = LINUXAPI_PREFIXED_SYM(dev_open),
	.d_close = LINUXAPI_PREFIXED_SYM(dev_close),
	.d_read = LINUXAPI_PREFIXED_SYM(dev_read),
	.d_write = LINUXAPI_PREFIXED_SYM(dev_write),
	.d_ioctl = LINUXAPI_PREFIXED_SYM(dev_ioctl),
	.d_mmap_single = LINUXAPI_PREFIXED_SYM(dev_mmap_single),
	.d_mmap = LINUXAPI_PREFIXED_SYM(dev_mmap),
	.d_poll = LINUXAPI_PREFIXED_SYM(dev_poll),
};

static int
LINUXAPI_PREFIXED_SYM(file_read)(struct file *file, struct uio *uio, struct ucred *active_cred,
    int flags, struct thread *td)
{
	struct linux_file *filp;
	ssize_t bytes;
	int error;

	error = 0;
	filp = (struct linux_file *)file->f_data;
	filp->f_flags = file->f_flag;
	if (uio->uio_iovcnt != 1)
		panic("linux_file_read: uio %p iovcnt %d",
		    uio, uio->uio_iovcnt);
	if (filp->f_op->read) {
		bytes = filp->f_op->read(filp, uio->uio_iov->iov_base,
		    uio->uio_iov->iov_len, &uio->uio_offset);
		if (bytes >= 0) {
			uio->uio_iov->iov_base =
			    ((uint8_t *)uio->uio_iov->iov_base) + bytes;
			uio->uio_iov->iov_len -= bytes;
			uio->uio_resid -= bytes;
		} else
			error = -bytes;
	} else
		error = ENXIO;

	return (error);
}

static int
LINUXAPI_PREFIXED_SYM(file_poll)(struct file *file, int events, struct ucred *active_cred,
    struct thread *td)
{
	struct linux_file *filp;
	int revents;

	filp = (struct linux_file *)file->f_data;
	filp->f_flags = file->f_flag;
	if (filp->f_op->poll)
		revents = filp->f_op->poll(filp, NULL) & events;
	else
		revents = 0;

	return (0);
}

static int
LINUXAPI_PREFIXED_SYM(file_close)(struct file *file, struct thread *td)
{
	struct linux_file *filp;
	int error;

	filp = (struct linux_file *)file->f_data;
	filp->f_flags = file->f_flag;
	error = -filp->f_op->release(NULL, filp);
	funsetown(&filp->f_sigio);
	kfree(filp);

	return (error);
}

static int
LINUXAPI_PREFIXED_SYM(file_ioctl)(struct file *fp, u_long cmd, void *data, struct ucred *cred,
    struct thread *td)
{
	struct linux_file *filp;
	int error;

	filp = (struct linux_file *)fp->f_data;
	filp->f_flags = fp->f_flag;
	error = 0;

	switch (cmd) {
	case FIONBIO:
		break;
	case FIOASYNC:
		if (filp->f_op->fasync == NULL)
			break;
		error = filp->f_op->fasync(0, filp, fp->f_flag & FASYNC);
		break;
	case FIOSETOWN:
		error = fsetown(*(int *)data, &filp->f_sigio);
		if (error == 0)
			error = filp->f_op->fasync(0, filp,
			    fp->f_flag & FASYNC);
		break;
	case FIOGETOWN:
		*(int *)data = fgetown(&filp->f_sigio);
		break;
	default:
		error = ENOTTY;
		break;
	}
	return (error);
}

static int
LINUXAPI_PREFIXED_SYM(file_stat)(struct file *fp, struct stat *sb, struct ucred *active_cred,
    struct thread *td)
{

	return (EOPNOTSUPP);
}

static int
LINUXAPI_PREFIXED_SYM(file_fill_kinfo)(struct file *fp, struct kinfo_file *kif,
    struct filedesc *fdp)
{

	return (0);
}

struct fileops LINUXAPI_PREFIXED_SYM(linuxfileops) = {
	.fo_read = LINUXAPI_PREFIXED_SYM(file_read),
	.fo_write = invfo_rdwr,
	.fo_truncate = invfo_truncate,
	.fo_kqfilter = invfo_kqfilter,
	.fo_stat = LINUXAPI_PREFIXED_SYM(file_stat),
	.fo_fill_kinfo = LINUXAPI_PREFIXED_SYM(file_fill_kinfo),
	.fo_poll = LINUXAPI_PREFIXED_SYM(file_poll),
	.fo_close = LINUXAPI_PREFIXED_SYM(file_close),
	.fo_ioctl = LINUXAPI_PREFIXED_SYM(file_ioctl),
	.fo_chmod = invfo_chmod,
	.fo_chown = invfo_chown,
	.fo_sendfile = invfo_sendfile,
};

static void
LINUXAPI_PREFIXED_SYM(device_release)(struct kobject *kobj)
{
	struct device *dev;

	dev = container_of(kobj, struct device, kobj);
	/* This is the precedence defined by linux. */
	if (dev->release)
		dev->release(dev);
	else if (dev->class && dev->class->dev_release)
		dev->class->dev_release(dev);
}

static ssize_t
LINUXAPI_PREFIXED_SYM(dev_show)(struct kobject *kobj, struct attribute *attr, char *buf)
{
	struct device_attribute *dattr;
	ssize_t error;

	dattr = container_of(attr, struct device_attribute, attr);
	error = -EIO;
	if (dattr->show)
		error = dattr->show(container_of(kobj, struct device, kobj),
		    dattr, buf);
	return (error);
}

static ssize_t
LINUXAPI_PREFIXED_SYM(dev_store)(struct kobject *kobj, struct attribute *attr, const char *buf,
    size_t count)
{
	struct device_attribute *dattr;
	ssize_t error;

	dattr = container_of(attr, struct device_attribute, attr);
	error = -EIO;
	if (dattr->store)
		error = dattr->store(container_of(kobj, struct device, kobj),
		    dattr, buf, count);
	return (error);
}

static struct sysfs_ops LINUXAPI_PREFIXED_SYM(dev_sysfs) = {
	.show  = LINUXAPI_PREFIXED_SYM(dev_show),
	.store = LINUXAPI_PREFIXED_SYM(dev_store),
};
struct kobj_type dev_ktype = {
	.release = LINUXAPI_PREFIXED_SYM(device_release),
	.sysfs_ops = &LINUXAPI_PREFIXED_SYM(dev_sysfs)
};

/*
 * Devices are registered and created for exporting to sysfs.  create
 * implies register and register assumes the device fields have been
 * setup appropriately before being called.
 */
int
device_register(struct device *dev)
{
	device_t bsddev;
	int unit;

	bsddev = NULL;
	if (dev->devt) {
		unit = MINOR(dev->devt);
		bsddev = devclass_get_device(dev->class->bsdclass, unit);
	} else
		unit = -1;
	if (bsddev == NULL)
		bsddev = device_add_child(dev->parent->bsddev,
		    dev->class->kobj.name, unit);
	if (bsddev) {
		if (dev->devt == 0)
			dev->devt = makedev(0, device_get_unit(bsddev));
		device_set_softc(bsddev, dev);
	}
	dev->bsddev = bsddev;
	kobject_init(&dev->kobj, &dev_ktype);
	kobject_add(&dev->kobj, &dev->class->kobj, dev_name(dev));

	return (0);
}

void
device_unregister(struct device *dev)
{
	device_t bsddev;

	bsddev = dev->bsddev;
	mtx_lock(&Giant);
	if (bsddev)
		device_delete_child(device_get_parent(bsddev), bsddev);
	mtx_unlock(&Giant);
	put_device(dev);
}

static void
LINUXAPI_PREFIXED_SYM(dev_release)(struct device *dev)
{
	pr_debug("dev_release: %s\n", dev_name(dev));
	kfree(dev);
}

struct device *
device_create(struct class *class, struct device *parent, dev_t devt,
    void *drvdata, const char *fmt, ...)
{
	struct device *dev;
	va_list args;

	dev = kzalloc(sizeof(*dev), M_WAITOK);
	dev->parent = parent;
	dev->class = class;
	dev->devt = devt;
	dev->driver_data = drvdata;
	dev->release = LINUXAPI_PREFIXED_SYM(dev_release);
	va_start(args, fmt);
	kobject_set_name_vargs(&dev->kobj, fmt, args);
	va_end(args);
	device_register(dev);

	return (dev);
}

void
device_destroy(struct class *class, dev_t devt)
{
	device_t bsddev;
	int unit;

	unit = MINOR(devt);
	bsddev = devclass_get_device(class->bsdclass, unit);
	if (bsddev)
		device_unregister(device_get_softc(bsddev));
}

int
device_create_file(struct device *dev, const struct device_attribute *attr)
{

	if (dev)
		return sysfs_create_file(&dev->kobj, &attr->attr);
	return -EINVAL;
}

void
device_remove_file(struct device *dev, const struct device_attribute *attr)
{

	if (dev)
		sysfs_remove_file(&dev->kobj, &attr->attr);
}
