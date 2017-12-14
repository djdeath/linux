/*
 * Copyright © 2017 Intel Corporation
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
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 */

#include "i915_drv.h"
#include <uapi/drm/i915_drm.h>

static int (* const i915_query_funcs[])(struct drm_i915_private *dev_priv,
					struct drm_i915_query_item *query_item) = {
};

int i915_query_ioctl(struct drm_device *dev, void *data, struct drm_file *file)
{
	struct drm_i915_private *dev_priv = to_i915(dev);
	struct drm_i915_query *args = data;
	struct drm_i915_query_item __user *user_item_ptr =
		u64_to_user_ptr(args->items_ptr);
	u32 i;

	if (args->flags != 0)
		return -EINVAL;

	for (i = 0; i < args->num_items; i++, user_item_ptr++) {
		struct drm_i915_query_item item;
		u64 func_idx;
		int ret;

		if (copy_from_user(&item, user_item_ptr, sizeof(item)))
			return -EFAULT;

		if (item.query_id == 0)
			return -EINVAL;

		func_idx = item.query_id - 1;

		if (func_idx >= ARRAY_SIZE(i915_query_funcs))
			return -EINVAL;

		ret = i915_query_funcs[func_idx](dev_priv, &item);

		/* Only write the length back to userspace if they differ. */
		if (ret != item.length && put_user(ret, &user_item_ptr->length))
			return -EFAULT;
	}

	return 0;
}
