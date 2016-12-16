/*
 * Copyright (C) 2016 Red Hat
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 * Rob Clark <robdclark@gmail.com>
 */

#ifndef DRM_PRINT_H_
#define DRM_PRINT_H_

#include <linux/compiler.h>
#include <linux/printk.h>
#include <linux/seq_file.h>
#include <linux/device.h>

/**
 * DOC: DRM Printer
 *
 * A simple wrapper for dev_printk(), seq_printf(), etc.  Allows same
 * debug code to be used for both debugfs and printk logging.
 *
 * For example::
 *
 *     void log_some_info(struct drm_printer *p)
 *     {
 *             drm_printf(p, "foo=%d\n", foo);
 *             drm_printf(p, "bar=%d\n", bar);
 *     }
 *
 *     #ifdef CONFIG_DEBUG_FS
 *     void debugfs_show(struct seq_file *f)
 *     {
 *             struct drm_printer p = drm_seq_file_printer(f);
 *             log_some_info(&p);
 *     }
 *     #endif
 *
 *     void some_other_function(...)
 *     {
 *             struct drm_printer p = drm_info_printer(drm->dev);
 *             log_some_info(&p);
 *     }
 */

/**
 * struct drm_printer - drm output "stream"
 *
 * Do not use struct members directly.  Use drm_printer_seq_file(),
 * drm_printer_info(), etc to initialize.  And drm_printf() for output.
 */
struct drm_printer {
	/* private */
	void (*printfn)(struct drm_printer *p, struct va_format *vaf);
	void *arg;
	const char *prefix;
};

void __drm_printfn_seq_file(struct drm_printer *p, struct va_format *vaf);
void __drm_printfn_info(struct drm_printer *p, struct va_format *vaf);
void __drm_printfn_debug(struct drm_printer *p, struct va_format *vaf);

__printf(2, 3)
void drm_printf(struct drm_printer *p, const char *f, ...);


/**
 * drm_seq_file_printer - construct a &drm_printer that outputs to &seq_file
 * @f:  the &struct seq_file to output to
 *
 * RETURNS:
 * The &drm_printer object
 */
static inline struct drm_printer drm_seq_file_printer(struct seq_file *f)
{
	struct drm_printer p = {
		.printfn = __drm_printfn_seq_file,
		.arg = f,
	};
	return p;
}

/**
 * drm_info_printer - construct a &drm_printer that outputs to dev_printk()
 * @dev: the &struct device pointer
 *
 * RETURNS:
 * The &drm_printer object
 */
static inline struct drm_printer drm_info_printer(struct device *dev)
{
	struct drm_printer p = {
		.printfn = __drm_printfn_info,
		.arg = dev,
	};
	return p;
}

/**
 * drm_debug_printer - construct a &drm_printer that outputs to pr_debug()
 * @prefix: debug output prefix
 *
 * RETURNS:
 * The &drm_printer object
 */
static inline struct drm_printer drm_debug_printer(const char *prefix)
{
	struct drm_printer p = {
		.printfn = __drm_printfn_debug,
		.prefix = prefix
	};
	return p;
}

/**
 * DOC: DRM Debug and Log Messages
 *
 * DRM exposes all debug message through the 'dynamic debug' infrastructure
 * if the kernel was built with
 * %CONFIG_DYNAMIC_DEBUG.
 *
 * Dynamic debug messages (ref: `Documentation/dynamic-debug-howto.txt`)
 * allow fine grained control over which debug messages are enabled with
 * runtime control via (`debugfs/dynamic_debug/control`)
 *
 * This provides more control than the previous `drm.drm_debug` parameter
 * which for some use cases was impractical to use given how verbose
 * some drm debug categories are.
 *
 * For example all debug messages in i915_drm.c can be enabled with:
 * `echo "file i915_perf.c +p" > dynamic_debug/control`
 */

/**
 * DOC: drm_debug categories
 *
 * Before enabling support for dynamic debug macros, DRM debug messages were
 * enabled and disabled using a `drm.drm_debug` parameter which could be
 * assigned a bitmask of category flags.
 *
 * Although more fine-grained control can now be had through the
 * `debugfs/dynamic_debug/control` interface, the drm_debug parameter is
 * still supported for backwards compatibility.
 * (See Documentation/dynamic-debug-howto.txt for more details)
 *
 * The following category flags are defined:
 *
 * - CORE, 0x1: Used in the generic drm code: drm_ioctl.c, drm_mm.c,
 *   drm_memory.c, ... This is the category used by the DRM_DEBUG() macro.
 *
 * - DRIVER, 0x2: Used in the vendor specific part of the driver: i915, radeon, ...
 *   This is the category used by the DRM_DEBUG_DRIVER() macro.
 *
 * - KMS, 0x4: used in the modesetting code.
 *   This is the category used by the DRM_DEBUG_KMS() macro.
 *
 * - PRIME, 0x8: used in the prime code.
 *   This is the category used by the DRM_DEBUG_PRIME() macro.
 *
 * - ATOMIC, 0x10: used in the atomic code.
 *   This is the category used by the DRM_DEBUG_ATOMIC() macro.
 *
 * - VBL, 0x20: used for verbose debug message in the vblank code
 *   This is the category used by the DRM_DEBUG_VBL() macro.
 *
 * Enabling verbose debug messages is done through the drm.debug parameter,
 * each category being enabled by a bit.
 *
 * drm.debug=0x1 will enable CORE messages
 * drm.debug=0x2 will enable DRIVER messages
 * drm.debug=0x3 will enable CORE and DRIVER messages
 * ...
 * drm.debug=0x3f will enable all messages
 *
 * An interesting feature is that it's possible to enable verbose logging at
 * run-time by echoing the debug value in its sysfs node:
 *   # echo 0xf > /sys/module/drm/parameters/debug
 */
#define DRM_UT_CORE 		0x01
#define _DRM_UT_core		0x01
#define DRM_UT_DRIVER		0x02
#define _DRM_UT_drv		0x02
#define DRM_UT_KMS		0x04
#define _DRM_UT_kms		0x04
#define DRM_UT_PRIME		0x08
#define _DRM_UT_prime		0x08
#define DRM_UT_ATOMIC		0x10
#define _DRM_UT_atomic		0x10
#define DRM_UT_VBL		0x20
#define _DRM_UT_vbl		0x20
#define DRM_UT_STATE		0x40

extern unsigned int drm_debug;

#define _DRM_PREFIX module_name(THIS_MODULE)

/***********************************************************************/
/** \name DRM template customization defaults */
/*@{*/

/***********************************************************************/
/** \name Macros to make printk easier */
/*@{*/

/**
 * DRM_INFO - Prints
 */
#define DRM_INFO(fmt, args...)						\
	pr_info("[%s] " fmt, _DRM_PREFIX, ##args)
#define DRM_NOTE(fmt, args...)						\
	pr_notice("[%s] " fmt, _DRM_PREFIX, ##args)
#define DRM_WARN(fmt, args...)						\
	pr_warn("[%s] " fmt, _DRM_PREFIX, ##args)

#define DRM_INFO_ONCE(fmt, args...)					\
	pr_info_once("[%s] " fmt, _DRM_PREFIX, ##args)
#define DRM_NOTE_ONCE(fmt, args...)					\
	pr_notice_once("[%s] " fmt, _DRM_PREFIX, ##args)
#define DRM_WARN_ONCE(fmt, args...)					\
	pr_warn_once("[%s] " fmt, _DRM_PREFIX, ##args)

/**
 * Error output.
 *
 * \param fmt printf() like format string.
 * \param arg arguments
 */
#define DRM_DEV_ERROR(dev, fmt, args...)				\
	dev_err(dev, "[%s:%s]*ERROR*" fmt, _DRM_PREFIX, __func__, ##args)
#define DRM_ERROR(fmt, args...)						\
	pr_err("[%s:%s]*ERROR*" fmt, _DRM_PREFIX, __func__, ##args)

/**
 * Rate limited error output.  Like DRM_ERROR() but won't flood the log.
 *
 * \param fmt printf() like format string.
 * \param arg arguments
 */
#define DRM_DEV_ERROR_RATELIMITED(dev, fmt, args...)			\
({									\
	static DEFINE_RATELIMIT_STATE(_rs,				\
				      DEFAULT_RATELIMIT_INTERVAL,	\
				      DEFAULT_RATELIMIT_BURST);		\
									\
	if (__ratelimit(&_rs))						\
		DRM_DEV_ERROR(dev, fmt, ##args);			\
})
#define DRM_ERROR_RATELIMITED(fmt, args...)				\
({									\
	static DEFINE_RATELIMIT_STATE(_rs,				\
				      DEFAULT_RATELIMIT_INTERVAL,	\
				      DEFAULT_RATELIMIT_BURST);		\
									\
	if (__ratelimit(&_rs))						\
		DRM_ERROR(fmt, ##args);					\
})

#define DRM_DEV_INFO(dev, fmt, args...)					\
	dev_info(dev, "[%s:%s] " fmt, _DRM_PREFIX, __func__, ##args)

#define DRM_DEV_INFO_ONCE(dev, fmt, args...)				\
	dev_info_once(dev, "[%s:%s] " fmt, _DRM_PREFIX, __func__, ##args)

/**
 * Debug output.
 *
 * \param fmt printf() like format string.
 * \param arg arguments
 */

#if defined(CONFIG_DYNAMIC_DEBUG)
#define DRM_DEF_DYN_DEBUG_DATA(name, fmt)				\
	DEFINE_DYNAMIC_DEBUG_METADATA(name, fmt);
#define DRM_DYN_DEBUG_BRANCH(descriptor)				\
	DYNAMIC_DEBUG_BRANCH(descriptor)

#define __drm_dyn_dev_dbg(descriptor, dev, fmt, args...)		\
	__dynamic_dev_dbg(descriptor, dev, fmt, ##args)
#define __drm_dyn_pr_debug(descriptor, fmt, args...)			\
	__dynamic_pr_debug(descriptor, fmt, ##args)
#else
#define DRM_DEF_DYN_DEBUG_DATA(name, fmt)	do {} while(0)
#define DRM_DYN_DEBUG_BRANCH(descriptor)	0

#define __drm_dyn_dev_dbg(descriptor, dev, fmt, args...)		\
	dev_dbg(dev, fmt, ##args)
#define __drm_dyn_pr_debug(descriptor, fmt, args...)			\
	pr_debug(fmt, ##args)
#endif

/* If modifying, note the duplication of the format strings for the
 * dynamic debug meta data and for passing to printk. We don't
 * deref descriptor->format to handle building without
 * CONFIG_DYNAMIC_DEBUG
 */
#define _DRM_DEV_DEBUG(dev, cat, fmt, args...)				\
({									\
	DRM_DEF_DYN_DEBUG_DATA(descriptor, "[%s:%s]["#cat"] " fmt);	\
	if (DRM_DYN_DEBUG_BRANCH(descriptor) ||				\
	    unlikely(drm_debug & _DRM_UT_##cat)) {			\
		__drm_dyn_dev_dbg(&descriptor, dev,			\
				  "[%s:%s]["#cat"] " fmt,		\
				  _DRM_PREFIX, __func__, ##args);	\
	}								\
})
#define _DRM_DEBUG(cat, fmt, args...)					\
({									\
	DRM_DEF_DYN_DEBUG_DATA(descriptor, "[%s:%s]["#cat"] " fmt);	\
	if (DRM_DYN_DEBUG_BRANCH(descriptor) ||				\
	    unlikely(drm_debug & _DRM_UT_##cat)) {			\
		__drm_dyn_pr_debug(&descriptor,				\
				   "[%s:%s]["#cat"] " fmt,		\
				   _DRM_PREFIX, __func__, ##args);	\
	}								\
})

#define DRM_DEV_DEBUG(dev, fmt, args...)				\
	_DRM_DEV_DEBUG(dev, core, fmt, ##args)
#define DRM_DEBUG(fmt, args...)						\
	_DRM_DEBUG(core, fmt, ##args)

#define DRM_DEV_DEBUG_DRIVER(dev, fmt, args...)				\
	_DRM_DEV_DEBUG(dev, drv, fmt, ##args)
#define DRM_DEBUG_DRIVER(fmt, args...)					\
	_DRM_DEBUG(drv, fmt, ##args)

#define DRM_DEV_DEBUG_KMS(dev, fmt, args...)				\
	_DRM_DEV_DEBUG(dev, kms, fmt, ##args)
#define DRM_DEBUG_KMS(fmt, args...)					\
	_DRM_DEBUG(kms, fmt, ##args)

#define DRM_DEV_DEBUG_PRIME(dev, fmt, args...)				\
	_DRM_DEV_DEBUG(dev, prime, fmt, ##args)
#define DRM_DEBUG_PRIME(fmt, args...)					\
	_DRM_DEBUG(prime, fmt, ##args)

#define DRM_DEV_DEBUG_ATOMIC(dev, fmt, args...)				\
	_DRM_DEV_DEBUG(dev, atomic, fmt, ##args)
#define DRM_DEBUG_ATOMIC(fmt, args...)					\
	_DRM_DEBUG(atomic, fmt, ##args)

#define DRM_DEV_DEBUG_VBL(dev, fmt, args...)				\
	_DRM_DEV_DEBUG(dev, vbl, fmt, ##args)
#define DRM_DEBUG_VBL(fmt, args...)					\
	_DRM_DEBUG(vbl, fmt, ##args)

#define _DRM_DEV_DEFINE_DEBUG_RATELIMITED(dev, category, fmt, args...)	\
({									\
	static DEFINE_RATELIMIT_STATE(_rs,				\
				      DEFAULT_RATELIMIT_INTERVAL,	\
				      DEFAULT_RATELIMIT_BURST);		\
	if (__ratelimit(&_rs))						\
		_DRM_DEV_DEBUG(dev, category, fmt, ##args);		\
})
#define _DRM_DEFINE_DEBUG_RATELIMITED(category, fmt, args...)	\
({									\
	static DEFINE_RATELIMIT_STATE(_rs,				\
				      DEFAULT_RATELIMIT_INTERVAL,	\
				      DEFAULT_RATELIMIT_BURST);		\
	if (__ratelimit(&_rs))						\
		_DRM_DEBUG(category, fmt, ##args);			\
})

/**
 * Rate limited debug output. Like DRM_DEBUG() but won't flood the log.
 *
 * \param fmt printf() like format string.
 * \param arg arguments
 */
#define DRM_DEV_DEBUG_RATELIMITED(dev, fmt, args...)			\
	_DRM_DEFINE_DEBUG_RATELIMITED(dev, core, fmt, ##args)
#define DRM_DEBUG_RATELIMITED(fmt, args...)				\
	_DRM_DEFINE_DEBUG_RATELIMITED(core, fmt, ##args)

#define DRM_DEV_DEBUG_DRIVER_RATELIMITED(dev, fmt, args...)		\
	_DRM_DEV_DEFINE_DEBUG_RATELIMITED(dev, drv, fmt, ##args)
#define DRM_DEBUG_DRIVER_RATELIMITED(fmt, args...)			\
	_DRM_DEV_DEFINE_DEBUG_RATELIMITED(drv, fmt, ##args)

#define DRM_DEV_DEBUG_KMS_RATELIMITED(dev, fmt, args...)		\
	_DRM_DEV_DEFINE_DEBUG_RATELIMITED(dev, kms, fmt, ##args)
#define DRM_DEBUG_KMS_RATELIMITED(fmt, args...)				\
	_DRM_DEFINE_DEBUG_RATELIMITED(kms, fmt, ##args)

#define DRM_DEV_DEBUG_PRIME_RATELIMITED(dev, fmt, args...)		\
	_DRM_DEV_DEFINE_DEBUG_RATELIMITED(dev, prime, fmt, ##args)
#define DRM_DEBUG_PRIME_RATELIMITED(fmt, args...)			\
	_DRM_DEFINE_DEBUG_RATELIMITED(prime, fmt, ##args)

/* Format strings and argument splitters to simplify printing
 * various "complex" objects
 */
#define DRM_MODE_FMT    "%d:\"%s\" %d %d %d %d %d %d %d %d %d %d 0x%x 0x%x"
#define DRM_MODE_ARG(m) \
	(m)->base.id, (m)->name, (m)->vrefresh, (m)->clock, \
	(m)->hdisplay, (m)->hsync_start, (m)->hsync_end, (m)->htotal, \
	(m)->vdisplay, (m)->vsync_start, (m)->vsync_end, (m)->vtotal, \
	(m)->type, (m)->flags

#define DRM_RECT_FMT    "%dx%d%+d%+d"
#define DRM_RECT_ARG(r) drm_rect_width(r), drm_rect_height(r), (r)->x1, (r)->y1

/* for rect's in fixed-point format: */
#define DRM_RECT_FP_FMT "%d.%06ux%d.%06u%+d.%06u%+d.%06u"
#define DRM_RECT_FP_ARG(r) \
		drm_rect_width(r) >> 16, ((drm_rect_width(r) & 0xffff) * 15625) >> 10, \
		drm_rect_height(r) >> 16, ((drm_rect_height(r) & 0xffff) * 15625) >> 10, \
		(r)->x1 >> 16, (((r)->x1 & 0xffff) * 15625) >> 10, \
		(r)->y1 >> 16, (((r)->y1 & 0xffff) * 15625) >> 10

/*@}*/


#endif /* DRM_PRINT_H_ */
