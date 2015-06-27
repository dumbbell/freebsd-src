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
#ifndef	_LINUX_DEVICE_H_
#define	_LINUX_DEVICE_H_

#include <linux/_linuxapi_shim.h>

#include <linux/kobject.h>
#include <linux/compiler.h> // Useless
#include <asm/atomic.h> // Useless
#include <linux/module.h> // Useless

#include <sys/bus.h>

enum irqreturn	{ IRQ_NONE = 0, IRQ_HANDLED, IRQ_WAKE_THREAD, };
typedef enum irqreturn	irqreturn_t;

struct class {
	const char	*name;
	struct module	*owner;
	struct kobject	kobj;
	devclass_t	bsdclass;
	void		(*class_release)(struct class *class);
	void		(*dev_release)(struct device *dev);
	char *		(*devnode)(struct device *dev, umode_t *mode);
};

struct device {
	struct device	*parent;
	struct list_head irqents;
	device_t	bsddev;
	dev_t		devt;
	struct class	*class;
	void		(*release)(struct device *dev);
	struct kobject	kobj;
	uint64_t	*dma_mask;
	void		*driver_data;
	unsigned int	irq;
	unsigned int	msix;
	unsigned int	msix_max;
};

#define linuxapi_rootdev LINUXAPI_PREFIXED_SYM(linuxapi_rootdev)
extern struct device linuxapi_rootdev;
#define class_root LINUXAPI_PREFIXED_SYM(class_root)
extern struct kobject class_root;

struct class_attribute {
        struct attribute attr;
        ssize_t (*show)(struct class *, struct class_attribute *, char *);
        ssize_t (*store)(struct class *, struct class_attribute *, const char *, size_t);
        const void *(*namespace)(struct class *, const struct class_attribute *);
};

#define	CLASS_ATTR(_name, _mode, _show, _store)				\
	struct class_attribute class_attr_##_name =			\
	    { { #_name, NULL, _mode }, _show, _store }

struct device_attribute {
	struct attribute	attr;
	ssize_t			(*show)(struct device *,
					struct device_attribute *, char *);
	ssize_t			(*store)(struct device *,
					struct device_attribute *, const char *,
					size_t);
};

#define	DEVICE_ATTR(_name, _mode, _show, _store)			\
	struct device_attribute dev_attr_##_name =			\
	    { { #_name, NULL, _mode }, _show, _store }

/* Simple class attribute that is just a static string */
struct class_attribute_string {
	struct class_attribute attr;
	char *str;
};

#define show_class_attr_string LINUXAPI_PREFIXED_SYM(show_class_attr_string)
ssize_t		show_class_attr_string(struct class *class,
		    struct class_attribute *attr, char *buf);

#define class_ktype LINUXAPI_PREFIXED_SYM(class_ktype)
extern struct kobj_type class_ktype;
#define dev_ktype LINUXAPI_PREFIXED_SYM(dev_ktype)
extern struct kobj_type dev_ktype;

/* Currently read-only only */
#define _CLASS_ATTR_STRING(_name, _mode, _str) \
	{ __ATTR(_name, _mode, show_class_attr_string, NULL), _str }
#define CLASS_ATTR_STRING(_name, _mode, _str) \
	struct class_attribute_string class_attr_##_name = \
		_CLASS_ATTR_STRING(_name, _mode, _str)

#define	dev_err(dev, fmt, ...)	device_printf((dev)->bsddev, fmt, ##__VA_ARGS__)
#define	dev_warn(dev, fmt, ...)	device_printf((dev)->bsddev, fmt, ##__VA_ARGS__)
#define	dev_info(dev, fmt, ...)	device_printf((dev)->bsddev, fmt, ##__VA_ARGS__)
#define	dev_printk(lvl, dev, fmt, ...)					\
	    device_printf((dev)->bsddev, fmt, ##__VA_ARGS__)

static inline void *
dev_get_drvdata(struct device *dev)
{

	return dev->driver_data;
}

static inline void
dev_set_drvdata(struct device *dev, void *data)
{

	dev->driver_data = data;
}

static inline struct device *
get_device(struct device *dev)
{

	if (dev)
		kobject_get(&dev->kobj);

	return (dev);
}

static inline char *
dev_name(const struct device *dev)
{

 	return kobject_name(&dev->kobj);
}

#define	dev_set_name(_dev, _fmt, ...)					\
	kobject_set_name(&(_dev)->kobj, (_fmt), ##__VA_ARGS__)

static inline void
put_device(struct device *dev)
{

	if (dev)
		kobject_put(&dev->kobj);
}

#define class_register LINUXAPI_PREFIXED_SYM(class_register)
int		class_register(struct class *class);
#define class_unregister LINUXAPI_PREFIXED_SYM(class_unregister)
void		class_unregister(struct class *class);
#define class_create LINUXAPI_PREFIXED_SYM(class_create)
struct class *	class_create(struct module *owner, const char *name);
#define class_destroy LINUXAPI_PREFIXED_SYM(class_destroy)
void		class_destroy(struct class *class);
#define class_create_file LINUXAPI_PREFIXED_SYM(class_create_file)
int		class_create_file(struct class *class,
		    const struct class_attribute *attr);
#define class_remove_file LINUXAPI_PREFIXED_SYM(class_remove_file)
void		class_remove_file(struct class *class,
		    const struct class_attribute *attr);

#define device_register LINUXAPI_PREFIXED_SYM(device_register)
int	device_register(struct device *dev);
#define device_unregister LINUXAPI_PREFIXED_SYM(device_unregister)
void	device_unregister(struct device *dev);

#define device_create LINUXAPI_PREFIXED_SYM(device_create)
struct device *device_create(struct class *class, struct device *parent,
	    dev_t devt, void *drvdata, const char *fmt, ...);
#define device_destroy LINUXAPI_PREFIXED_SYM(device_destroy)
void	device_destroy(struct class *class, dev_t devt);
#define device_create_file LINUXAPI_PREFIXED_SYM(device_create_file)
int	device_create_file(struct device *dev,
	    const struct device_attribute *attr);
#define device_remove_file LINUXAPI_PREFIXED_SYM(device_remove_file)
void	device_remove_file(struct device *dev,
	    const struct device_attribute *attr);

static inline int dev_to_node(struct device *dev)
{
                return -1;
}

#define kvasprintf LINUXAPI_PREFIXED_SYM(kvasprintf)
char *kvasprintf(gfp_t gfp, const char *fmt, va_list ap);
#define kasprintf LINUXAPI_PREFIXED_SYM(kasprintf)
char *kasprintf(gfp_t, const char *, ...);

#endif	/* _LINUX_DEVICE_H_ */
