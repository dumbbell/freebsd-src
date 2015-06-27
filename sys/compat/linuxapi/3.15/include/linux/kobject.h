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
#ifndef	_LINUX_KOBJECT_H_
#define	_LINUX_KOBJECT_H_

#include <linux/_linuxapi_shim.h>

#include <sys/param.h>

#include <machine/stdarg.h>

#include <linux/kernel.h>
#include <linux/kref.h>

struct kobject;
struct sysctl_oid;

struct kobj_type {
	void (*release)(struct kobject *kobj);
	const struct sysfs_ops *sysfs_ops;
	struct attribute **default_attrs;
};

#define	kfree_type LINUXAPI_PREFIXED_SYM(kfree_type)
extern struct kobj_type kfree_type;

struct kobject {
	struct kobject		*parent;
	char			*name;
	struct kref		kref;
	struct kobj_type	*ktype;
	struct list_head	entry;
	struct sysctl_oid	*oidp;
};

#define kobject_init_and_add LINUXAPI_PREFIXED_SYM(kobject_init_and_add)
int	kobject_init_and_add(struct kobject *kobj, struct kobj_type *ktype,
	    struct kobject *parent, const char *fmt, ...);
#define kobject_init LINUXAPI_PREFIXED_SYM(kobject_init)
void	kobject_init(struct kobject *kobj, struct kobj_type *ktype);

#define kobject_create LINUXAPI_PREFIXED_SYM(kobject_create)
struct kobject * kobject_create(void);
#define kobject_create_and_add LINUXAPI_PREFIXED_SYM(kobject_create_and_add)
struct kobject * kobject_create_and_add(const char *name, struct kobject *parent);

#define kobject_add LINUXAPI_PREFIXED_SYM(kobject_add)
int	kobject_add(struct kobject *kobj, struct kobject *parent,
	    const char *fmt, ...);
#define kobject_get LINUXAPI_PREFIXED_SYM(kobject_get)
struct kobject * kobject_get(struct kobject *kobj);
#define kobject_put LINUXAPI_PREFIXED_SYM(kobject_put)
void	kobject_put(struct kobject *kobj);
#define kobject_name LINUXAPI_PREFIXED_SYM(kobject_name)
char *	kobject_name(const struct kobject *kobj);
#define kobject_set_name LINUXAPI_PREFIXED_SYM(kobject_set_name)
int	kobject_set_name(struct kobject *kobj, const char *fmt, ...);
#define kobject_set_name_vargs LINUXAPI_PREFIXED_SYM(kobject_set_name_vargs)
int	kobject_set_name_vargs(struct kobject *kobj, const char *fmt,
	    va_list args);
#define kobject_kfree_name LINUXAPI_PREFIXED_SYM(kobject_kfree_name)
void	kobject_kfree_name(struct kobject *kobj);

/* sysfs.h calles for 'kobject' which is defined here, 
 * so we need to add the include only after the 'kobject' def.
 */
#include <linux/sysfs.h>

struct kobj_attribute {
        struct attribute attr;
        ssize_t (*show)(struct kobject *kobj, struct kobj_attribute *attr,
                        char *buf);
        ssize_t (*store)(struct kobject *kobj, struct kobj_attribute *attr,
                         const char *buf, size_t count);
};

#endif /* _LINUX_KOBJECT_H_ */
