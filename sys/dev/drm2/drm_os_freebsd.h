/**
 * \file drm_os_freebsd.h
 * OS abstraction macros.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <linux/types.h>

#include <sys/fbio.h>

#define	unlikely(x)            __builtin_expect(!!(x), 0)
#define	likely(x)              __builtin_expect(!!(x), 1)

#define DRM_HZ			hz
#define DRM_UDELAY(udelay)	DELAY(udelay)
#define DRM_MDELAY(msecs)	do { int loops = (msecs);		\
				  while (loops--) DELAY(1000);		\
				} while (0)
#define DRM_MSLEEP(msecs)	drm_msleep((msecs), "drm_msleep")
#define DRM_TIME_SLICE		(hz/20)  /* Time slice for GLXContexts	  */

#define	do_div(a, b)		((a) /= (b))
#define	lower_32_bits(n)	((u32)(n))

#define	memset_io(a, b, c)	memset((a), (b), (c))
#define	memcpy_fromio(a, b, c)	memcpy((a), (b), (c))
#define	memcpy_toio(a, b, c)	memcpy((a), (b), (c))

/* XXXKIB what is the right code for the FreeBSD ? */
/* kib@ used ENXIO here -- dumbbell@ */
#define	EREMOTEIO	EIO
#define	ERESTARTSYS	ERESTART

#define	KTR_DRM		KTR_DEV
#define	KTR_DRM_REG	KTR_SPARE3

#define	PCI_VENDOR_ID_APPLE		0x106b
#define	PCI_VENDOR_ID_ASUSTEK		0x1043
#define	PCI_VENDOR_ID_ATI		0x1002
#define	PCI_VENDOR_ID_DELL		0x1028
#define	PCI_VENDOR_ID_HP		0x103c
#define	PCI_VENDOR_ID_IBM		0x1014
#define	PCI_VENDOR_ID_INTEL		0x8086
#define	PCI_VENDOR_ID_SERVERWORKS	0x1166
#define	PCI_VENDOR_ID_SONY		0x104d
#define	PCI_VENDOR_ID_VIA		0x1106

#define	hweight32(i)	bitcount32(i)

/**
 * ror32 - rotate a 32-bit value right
 * @word: value to rotate
 * @shift: bits to roll
 *
 * Source: include/linux/bitops.h
 */
static inline uint32_t ror32(uint32_t word, unsigned int shift)
{
	return (word >> shift) | (word << (32 - shift));
}

#define	IS_ALIGNED(x, y)	(((x) & ((y) - 1)) == 0)
#define	get_unaligned(ptr)                                              \
	({ __typeof__(*(ptr)) __tmp;                                    \
	  memcpy(&__tmp, (ptr), sizeof(*(ptr))); __tmp; })

#if _BYTE_ORDER == _LITTLE_ENDIAN
/* Taken from linux/include/linux/unaligned/le_struct.h. */
struct __una_u32 { u32 x; } __packed;

static inline u32 __get_unaligned_cpu32(const void *p)
{
	const struct __una_u32 *ptr = (const struct __una_u32 *)p;
	return ptr->x;
}

static inline u32 get_unaligned_le32(const void *p)
{
	return __get_unaligned_cpu32((const u8 *)p);
}
#else
/* Taken from linux/include/linux/unaligned/le_byteshift.h. */
static inline u32 __get_unaligned_le32(const u8 *p)
{
	return p[0] | p[1] << 8 | p[2] << 16 | p[3] << 24;
}

static inline u32 get_unaligned_le32(const void *p)
{
	return __get_unaligned_le32((const u8 *)p);
}
#endif

#define KIB_NOTYET()							\
do {									\
	if (drm_debug_flag && drm_notyet_flag)				\
		printf("NOTYET: %s at %s:%d\n", __func__, __FILE__, __LINE__); \
} while (0)
