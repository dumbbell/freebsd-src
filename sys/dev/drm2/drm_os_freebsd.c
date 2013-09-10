
#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <dev/drm2/drmP.h>

devclass_t drm_devclass;

static drm_pci_id_list_t *
drm_find_description(int vendor, int device, drm_pci_id_list_t *idlist)
{
	int i = 0;

	for (i = 0; idlist[i].vendor != 0; i++) {
		if ((idlist[i].vendor == vendor) &&
		    ((idlist[i].device == device) ||
		    (idlist[i].device == 0))) {
			return (&idlist[i]);
		}
	}
	return (NULL);
}

/*
 * drm_probe_helper: called by a driver at the end of its probe
 * method.
 */
int
drm_probe_helper(device_t kdev, drm_pci_id_list_t *idlist)
{
	drm_pci_id_list_t *id_entry;
	int vendor, device;

	vendor = pci_get_vendor(kdev);
	device = pci_get_device(kdev);

	if (pci_get_class(kdev) != PCIC_DISPLAY ||
	    pci_get_subclass(kdev) != PCIS_DISPLAY_VGA)
		return (ENXIO);

	id_entry = drm_find_description(vendor, device, idlist);
	if (id_entry != NULL) {
		if (device_get_desc(kdev) == NULL) {
			DRM_DEBUG("%s desc: %s\n",
			    device_get_nameunit(kdev), id_entry->name);
			device_set_desc(kdev, id_entry->name);
		}
		return (0);
	}

	return (ENXIO);
}

/*
 * drm_attach_helper: called by a driver at the end of its attach
 * method.
 */
int
drm_attach_helper(device_t kdev, drm_pci_id_list_t *idlist,
    struct drm_driver *driver)
{
	struct drm_device *dev;
	int vendor, device;
	int ret;

	dev = device_get_softc(kdev);

	vendor = pci_get_vendor(kdev);
	device = pci_get_device(kdev);
	dev->id_entry = drm_find_description(vendor, device, idlist);

	ret = drm_get_pci_dev(kdev, dev, driver);

	return (ret);
}

int
drm_generic_detach(device_t kdev)
{
	struct drm_device *dev;
	int i;

	dev = device_get_softc(kdev);

	drm_put_dev(dev);

	/* Clean up PCI resources allocated by drm_bufs.c.  We're not really
	 * worried about resource consumption while the DRM is inactive (between
	 * lastclose and firstopen or unload) because these aren't actually
	 * taking up KVA, just keeping the PCI resource allocated.
	 */
	for (i = 0; i < DRM_MAX_PCI_RESOURCE; i++) {
		if (dev->pcir[i] == NULL)
			continue;
		bus_release_resource(dev->dev, SYS_RES_MEMORY,
		    dev->pcirid[i], dev->pcir[i]);
		dev->pcir[i] = NULL;
	}

	if (pci_disable_busmaster(dev->dev))
		DRM_ERROR("Request to disable bus-master failed.\n");

	return (0);
}

int
drm_add_busid_modesetting(struct drm_device *dev, struct sysctl_ctx_list *ctx,
    struct sysctl_oid *top)
{
	struct sysctl_oid *oid;

	snprintf(dev->busid_str, sizeof(dev->busid_str),
	     "pci:%04x:%02x:%02x.%d", dev->pci_domain, dev->pci_bus,
	     dev->pci_slot, dev->pci_func);
	oid = SYSCTL_ADD_STRING(ctx, SYSCTL_CHILDREN(top), OID_AUTO, "busid",
	    CTLFLAG_RD, dev->busid_str, 0, NULL);
	if (oid == NULL)
		return (ENOMEM);
	dev->modesetting = (dev->driver->driver_features & DRIVER_MODESET) != 0;
	oid = SYSCTL_ADD_INT(ctx, SYSCTL_CHILDREN(top), OID_AUTO,
	    "modesetting", CTLFLAG_RD, &dev->modesetting, 0, NULL);
	if (oid == NULL)
		return (ENOMEM);

	return (0);
}

bool
dmi_check_system(const struct dmi_system_id *sysid)
{

	/* XXXKIB */
	return (false);
}

#if DRM_LINUX

#include <sys/sysproto.h>

MODULE_DEPEND(DRIVER_NAME, linux, 1, 1, 1);

#define LINUX_IOCTL_DRM_MIN		0x6400
#define LINUX_IOCTL_DRM_MAX		0x64ff

static linux_ioctl_function_t drm_linux_ioctl;
static struct linux_ioctl_handler drm_handler = {drm_linux_ioctl,
    LINUX_IOCTL_DRM_MIN, LINUX_IOCTL_DRM_MAX};

/* The bits for in/out are switched on Linux */
#define LINUX_IOC_IN	IOC_OUT
#define LINUX_IOC_OUT	IOC_IN

static int
drm_linux_ioctl(DRM_STRUCTPROC *p, struct linux_ioctl_args* args)
{
	int error;
	int cmd = args->cmd;

	args->cmd &= ~(LINUX_IOC_IN | LINUX_IOC_OUT);
	if (cmd & LINUX_IOC_IN)
		args->cmd |= IOC_IN;
	if (cmd & LINUX_IOC_OUT)
		args->cmd |= IOC_OUT;

	error = ioctl(p, (struct ioctl_args *)args);

	return error;
}
#endif /* DRM_LINUX */

static int
drm_modevent(module_t mod, int type, void *data)
{

	switch (type) {
	case MOD_LOAD:
		TUNABLE_INT_FETCH("drm.debug", &drm_debug);
		TUNABLE_INT_FETCH("drm.notyet", &drm_notyet);
		break;
	}
	return (0);
}

static moduledata_t drm_mod = {
	"drmn",
	drm_modevent,
	0
};

DECLARE_MODULE(drmn, drm_mod, SI_SUB_DRIVERS, SI_ORDER_FIRST);
MODULE_VERSION(drmn, 1);
MODULE_DEPEND(drmn, agp, 1, 1, 1);
MODULE_DEPEND(drmn, pci, 1, 1, 1);
MODULE_DEPEND(drmn, mem, 1, 1, 1);
MODULE_DEPEND(drmn, iicbus, 1, 1, 1);
