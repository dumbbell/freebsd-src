/*-
 * Copyright 2003 Eric Anholt
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
 * ERIC ANHOLT BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

/** @file drm_sysctl.c
 * Implementation of various sysctls for controlling DRM behavior and reporting
 * debug information.
 */

#include <dev/drm2/drmP.h>
#include <dev/drm2/drm.h>

#include <sys/mount.h>
#include <sys/sysctl.h>

static int	   drm_name_info DRM_SYSCTL_HANDLER_ARGS;
static int	   drm_driver_name_info DRM_SYSCTL_HANDLER_ARGS;
static int	   drm_vendor_id_info DRM_SYSCTL_HANDLER_ARGS;
static int	   drm_device_id_info DRM_SYSCTL_HANDLER_ARGS;
static int	   drm_subvendor_id_info DRM_SYSCTL_HANDLER_ARGS;
static int	   drm_subdevice_id_info DRM_SYSCTL_HANDLER_ARGS;
static int	   drm_dev_path_info DRM_SYSCTL_HANDLER_ARGS;
static int	   drm_vm_info DRM_SYSCTL_HANDLER_ARGS;
static int	   drm_clients_info DRM_SYSCTL_HANDLER_ARGS;
static int	   drm_bufs_info DRM_SYSCTL_HANDLER_ARGS;
static int	   drm_vblank_info DRM_SYSCTL_HANDLER_ARGS;

struct drm_sysctl_list {
	const char *name;
	int         kind;
	int	   (*f) DRM_SYSCTL_HANDLER_ARGS;
	const char *format;
	const char *descr;
} drm_sysctl_list[] = {
	{"name",            CTLTYPE_STRING, drm_name_info, "A", NULL},
	{"driver_name",     CTLTYPE_STRING, drm_driver_name_info, "A", "Kernel driver name"},
	{"vendor_id",       CTLTYPE_UINT, drm_vendor_id_info, "IU",
		"Vendor ID"},
	{"device_id",       CTLTYPE_UINT, drm_device_id_info, "IU",
		"Device ID"},
	{"subvendor_id",    CTLTYPE_UINT, drm_subvendor_id_info, "IU",
		"Sub-vendor ID"},
	{"subdevice_id",    CTLTYPE_UINT, drm_subdevice_id_info, "IU",
		"Sub-device ID"},
	{"dev_path", CTLTYPE_STRING, drm_dev_path_info, "A",
		"Device path (relative to devfs mountpoint)"},
	{"vm",	            CTLTYPE_STRING, drm_vm_info, "A", NULL},
	{"clients",         CTLTYPE_STRING, drm_clients_info, "A", NULL},
	{"bufs",            CTLTYPE_STRING, drm_bufs_info, "A", NULL},
	{"vblank",          CTLTYPE_STRING, drm_vblank_info, "A", NULL},
};
#define DRM_SYSCTL_ENTRIES (sizeof(drm_sysctl_list)/sizeof(drm_sysctl_list[0]))

struct drm_sysctl_info {
	struct sysctl_ctx_list ctx;
	char		       name[5];
};

int drm_sysctl_init(struct drm_device *dev)
{
	struct drm_sysctl_info *info;
	struct sysctl_oid *drioid;

	info = malloc(sizeof *info, DRM_MEM_DRIVER, M_WAITOK | M_ZERO);
	dev->sysctl = info;

	/* Add the sysctl node for DRI if it doesn't already exist */
	drioid = SYSCTL_ADD_NODE(&info->ctx, &sysctl__hw_children, OID_AUTO,
	    "dri", CTLFLAG_RW, NULL, "DRI Graphics");
	if (!drioid) {
		free(dev->sysctl, DRM_MEM_DRIVER);
		dev->sysctl = NULL;
		return 1;
	}

	SYSCTL_ADD_INT(&info->ctx, SYSCTL_CHILDREN(drioid), OID_AUTO, "debug",
	    CTLFLAG_RW, &drm_debug, sizeof(drm_debug),
	    "Enable debugging output");
	SYSCTL_ADD_INT(&info->ctx, SYSCTL_CHILDREN(drioid), OID_AUTO, "notyet",
	    CTLFLAG_RW, &drm_notyet, sizeof(drm_debug),
	    "Enable notyet reminders");

	SYSCTL_ADD_INT(&info->ctx, SYSCTL_CHILDREN(drioid), OID_AUTO,
	    "vblank_offdelay", CTLFLAG_RW, &drm_vblank_offdelay,
	    sizeof(drm_vblank_offdelay),
	    "");
	SYSCTL_ADD_INT(&info->ctx, SYSCTL_CHILDREN(drioid), OID_AUTO,
	    "timestamp_precision", CTLFLAG_RW, &drm_timestamp_precision,
	    sizeof(drm_timestamp_precision),
	    "");

	return (0);
}

int drm_sysctl_cleanup(struct drm_device *dev)
{
	int error;

	if (dev->sysctl == NULL)
		return (0);

	error = sysctl_ctx_free(&dev->sysctl->ctx);
	free(dev->sysctl, DRM_MEM_DRIVER);
	dev->sysctl = NULL;

	return (error);
}

int
drm_sysctl_add_minor(struct drm_minor *minor)
{
	struct drm_sysctl_info *info;
	struct sysctl_oid *drioid, *top, *oid;
	int i;

	info = malloc(sizeof(*info), DRM_MEM_DRIVER, M_WAITOK | M_ZERO);
	minor->sysctl = info;

	/* Add the sysctl node for DRI if it doesn't already exist */
	drioid = SYSCTL_ADD_NODE(&info->ctx, &sysctl__hw_children, OID_AUTO,
	    "dri", CTLFLAG_RW, NULL, "DRI Graphics");
	if (!drioid) {
		free(minor->sysctl, DRM_MEM_DRIVER);
		minor->sysctl = NULL;
		return 1;
	}

	minor->sysctl_node_idx = dev2udev(minor->device);
	/* Add the hw.dri.x for our device */
	snprintf(info->name, sizeof(info->name), "0x%02x", minor->sysctl_node_idx);
	top = SYSCTL_ADD_NODE(&info->ctx, SYSCTL_CHILDREN(drioid),
	    minor->sysctl_node_idx, info->name, CTLFLAG_RW, NULL, NULL);
	if (!top) {
		drm_sysctl_remove_minor(minor);
		return 1;
	}

	for (i = 0; i < DRM_SYSCTL_ENTRIES; i++) {
		oid = SYSCTL_ADD_OID(&info->ctx,
			SYSCTL_CHILDREN(top),
			OID_AUTO,
			drm_sysctl_list[i].name,
			drm_sysctl_list[i].kind | CTLFLAG_RD,
			minor,
			0,
			drm_sysctl_list[i].f,
			drm_sysctl_list[i].format,
			drm_sysctl_list[i].descr);
		if (!oid) {
			drm_sysctl_remove_minor(minor);
			return 1;
		}
	}

	if (minor->dev->driver->sysctl_init != NULL)
		minor->dev->driver->sysctl_init(minor, &info->ctx, top);

	return (0);
}

int
drm_sysctl_remove_minor(struct drm_minor *minor)
{
	int error;

	if (
	    minor->sysctl == NULL)
		return (0);

	error = sysctl_ctx_free(&minor->sysctl->ctx);
	free(minor->sysctl, DRM_MEM_DRIVER);
	minor->sysctl = NULL;
	if (minor->dev->driver->sysctl_cleanup != NULL)
		minor->dev->driver->sysctl_cleanup(minor);

	return (error);
}

#define DRM_SYSCTL_PRINT(fmt, arg...)				\
do {								\
	snprintf(buf, sizeof(buf), fmt, ##arg);			\
	retcode = SYSCTL_OUT(req, buf, strlen(buf));		\
	if (retcode)						\
		goto done;					\
} while (0)

static int drm_name_info DRM_SYSCTL_HANDLER_ARGS
{
	struct drm_minor *minor = arg1;
	struct drm_device *dev;
	struct drm_master *master;
	char buf[128];
	int retcode;
	int hasunique = 0;

	dev = minor->dev;
	DRM_SYSCTL_PRINT("%s 0x%x", dev->driver->name, dev2udev(minor->device));

	DRM_LOCK(dev);
	master = minor->master;
	if (master != NULL && master->unique) {
		snprintf(buf, sizeof(buf), " %s", master->unique);
		hasunique = 1;
	}
	DRM_UNLOCK(dev);

	if (hasunique)
		SYSCTL_OUT(req, buf, strlen(buf));

	SYSCTL_OUT(req, "", 1);

done:
	return retcode;
}

static int drm_driver_name_info DRM_SYSCTL_HANDLER_ARGS
{
	struct drm_minor *minor = arg1;
	struct drm_device *dev;
	char buf[128];
	int retcode;

	dev = minor->dev;
	DRM_SYSCTL_PRINT("%s", dev->driver->name);

	SYSCTL_OUT(req, "", 1);

done:
	return retcode;
}

static int drm_vendor_id_info DRM_SYSCTL_HANDLER_ARGS
{
	struct drm_minor *minor = arg1;
	struct drm_device *dev;
	uint32_t vendor_id;
	int retcode;

	dev = minor->dev;
	vendor_id = dev->pci_vendor;
	retcode = SYSCTL_OUT(req, &vendor_id, sizeof(vendor_id));

	return retcode;
}

static int drm_device_id_info DRM_SYSCTL_HANDLER_ARGS
{
	struct drm_minor *minor = arg1;
	struct drm_device *dev;
	uint32_t device_id;
	int retcode;

	dev = minor->dev;
	device_id = dev->pci_device;
	retcode = SYSCTL_OUT(req, &device_id, sizeof(device_id));

	return retcode;
}

static int drm_subvendor_id_info DRM_SYSCTL_HANDLER_ARGS
{
	struct drm_minor *minor = arg1;
	struct drm_device *dev;
	uint32_t subvendor_id;
	int retcode;

	dev = minor->dev;
	subvendor_id = dev->pci_subvendor;
	retcode = SYSCTL_OUT(req, &subvendor_id, sizeof(subvendor_id));

	return retcode;
}

static int drm_subdevice_id_info DRM_SYSCTL_HANDLER_ARGS
{
	struct drm_minor *minor = arg1;
	struct drm_device *dev;
	uint32_t subdevice_id;
	int retcode;

	dev = minor->dev;
	subdevice_id = dev->pci_subdevice;
	retcode = SYSCTL_OUT(req, &subdevice_id, sizeof(subdevice_id));

	return retcode;
}

static int drm_dev_path_info DRM_SYSCTL_HANDLER_ARGS
{
	struct drm_minor *minor = arg1;
	char buf[MAXPATHLEN + 1];
	int retcode;

	DRM_SYSCTL_PRINT("%s", minor->device->si_name);

	SYSCTL_OUT(req, "", 1);

done:
	return retcode;
}

static int drm_vm_info DRM_SYSCTL_HANDLER_ARGS
{
	struct drm_minor *minor = arg1;
	struct drm_device *dev;
	struct drm_map_list *entry;
	struct drm_local_map *map, *tempmaps;
	const char *types[] = {
		[_DRM_FRAME_BUFFER] = "FB",
		[_DRM_REGISTERS] = "REG",
		[_DRM_SHM] = "SHM",
		[_DRM_AGP] = "AGP",
		[_DRM_SCATTER_GATHER] = "SG",
		[_DRM_CONSISTENT] = "CONS",
		[_DRM_GEM] = "GEM"
	};
	const char *type, *yesno;
	int i, mapcount;
	char buf[128];
	int retcode;

	/* We can't hold the lock while doing SYSCTL_OUTs, so allocate a
	 * temporary copy of all the map entries and then SYSCTL_OUT that.
	 */
	dev = minor->dev;
	DRM_LOCK(dev);

	mapcount = 0;
	list_for_each_entry(entry, &dev->maplist, head) {
		if (entry->map != NULL)
			mapcount++;
	}

	tempmaps = malloc(sizeof(*tempmaps) * mapcount, DRM_MEM_DRIVER,
	    M_NOWAIT);
	if (tempmaps == NULL) {
		DRM_UNLOCK(dev);
		return ENOMEM;
	}

	i = 0;
	list_for_each_entry(entry, &dev->maplist, head) {
		if (entry->map != NULL)
			tempmaps[i++] = *entry->map;
	}

	DRM_UNLOCK(dev);

	DRM_SYSCTL_PRINT("\nslot offset	        size       "
	    "type flags address            mtrr\n");

	for (i = 0; i < mapcount; i++) {
		map = &tempmaps[i];

		switch(map->type) {
		default:
			type = "??";
			break;
		case _DRM_FRAME_BUFFER:
		case _DRM_REGISTERS:
		case _DRM_SHM:
		case _DRM_AGP:
		case _DRM_SCATTER_GATHER:
		case _DRM_CONSISTENT:
		case _DRM_GEM:
			type = types[map->type];
			break;
		}

		if (map->mtrr < 0)
			yesno = "no";
		else
			yesno = "yes";

		DRM_SYSCTL_PRINT(
		    "%4d 0x%016lx 0x%08lx %4.4s  0x%02x 0x%016lx %s\n",
		    i, map->offset, map->size, type, map->flags,
		    (unsigned long)map->handle, yesno);
	}
	SYSCTL_OUT(req, "", 1);

done:
	free(tempmaps, DRM_MEM_DRIVER);
	return retcode;
}

static int drm_bufs_info DRM_SYSCTL_HANDLER_ARGS
{
	struct drm_minor *minor = arg1;
	struct drm_device *dev;
	drm_device_dma_t *dma;
	drm_device_dma_t tempdma;
	int *templists;
	int i;
	char buf[128];
	int retcode;

	/* We can't hold the locks around DRM_SYSCTL_PRINT, so make a temporary
	 * copy of the whole structure and the relevant data from buflist.
	 */
	dev = minor->dev;
	dma = dev->dma;
	DRM_LOCK(dev);
	if (dma == NULL) {
		DRM_UNLOCK(dev);
		return 0;
	}
	DRM_SPINLOCK(&dev->dma_lock);
	tempdma = *dma;
	templists = malloc(sizeof(int) * dma->buf_count, DRM_MEM_DRIVER,
	    M_NOWAIT);
	for (i = 0; i < dma->buf_count; i++)
		templists[i] = dma->buflist[i]->list;
	dma = &tempdma;
	DRM_SPINUNLOCK(&dev->dma_lock);
	DRM_UNLOCK(dev);

	DRM_SYSCTL_PRINT("\n o     size count  free	 segs pages    kB\n");
	for (i = 0; i <= DRM_MAX_ORDER; i++) {
		if (dma->bufs[i].buf_count)
			DRM_SYSCTL_PRINT("%2d %8d %5d %5d %5d %5d %5d\n",
				       i,
				       dma->bufs[i].buf_size,
				       dma->bufs[i].buf_count,
				       atomic_read(&dma->bufs[i]
						   .freelist.count),
				       dma->bufs[i].seg_count,
				       dma->bufs[i].seg_count
				       *(1 << dma->bufs[i].page_order),
				       (dma->bufs[i].seg_count
					* (1 << dma->bufs[i].page_order))
				       * (int)PAGE_SIZE / 1024);
	}
	DRM_SYSCTL_PRINT("\n");
	for (i = 0; i < dma->buf_count; i++) {
		if (i && !(i%32)) DRM_SYSCTL_PRINT("\n");
		DRM_SYSCTL_PRINT(" %d", templists[i]);
	}
	DRM_SYSCTL_PRINT("\n");

	SYSCTL_OUT(req, "", 1);
done:
	free(templists, DRM_MEM_DRIVER);
	return retcode;
}

static int drm_clients_info DRM_SYSCTL_HANDLER_ARGS
{
	struct drm_minor *minor = arg1;
	struct drm_device *dev;
	struct drm_file *priv, *tempprivs;
	char buf[128];
	int retcode;
	int privcount, i;

	dev = minor->dev;
	DRM_LOCK(dev);

	privcount = 0;
	list_for_each_entry(priv, &dev->filelist, lhead)
		privcount++;

	tempprivs = malloc(sizeof(struct drm_file) * privcount, DRM_MEM_DRIVER,
	    M_NOWAIT);
	if (tempprivs == NULL) {
		DRM_UNLOCK(dev);
		return ENOMEM;
	}
	i = 0;
	list_for_each_entry(priv, &dev->filelist, lhead)
		tempprivs[i++] = *priv;

	DRM_UNLOCK(dev);

	DRM_SYSCTL_PRINT(
	    "\na dev            pid   uid      magic     ioctls\n");
	for (i = 0; i < privcount; i++) {
		priv = &tempprivs[i];
		DRM_SYSCTL_PRINT("%c %-12s %5d %5d %10u %10lu\n",
			       priv->authenticated ? 'y' : 'n',
			       devtoname(priv->minor->device),
			       priv->pid,
			       priv->uid,
			       priv->magic,
			       priv->ioctl_count);
	}

	SYSCTL_OUT(req, "", 1);
done:
	free(tempprivs, DRM_MEM_DRIVER);
	return retcode;
}

static int drm_vblank_info DRM_SYSCTL_HANDLER_ARGS
{
	struct drm_minor *minor = arg1;
	struct drm_device *dev;
	char buf[128];
	int retcode;
	int i;

	dev = minor->dev;

	DRM_SYSCTL_PRINT("\ncrtc ref count    last     enabled inmodeset\n");
	DRM_LOCK(dev);
	if (dev->_vblank_count == NULL)
		goto done;
	for (i = 0 ; i < dev->num_crtcs ; i++) {
		DRM_SYSCTL_PRINT("  %02d  %02d %08d %08d %02d      %02d\n",
		    i, dev->vblank_refcount[i],
		    dev->_vblank_count[i],
		    dev->last_vblank[i],
		    dev->vblank_enabled[i],
		    dev->vblank_inmodeset[i]);
	}
done:
	DRM_UNLOCK(dev);

	SYSCTL_OUT(req, "", -1);
	return retcode;
}
