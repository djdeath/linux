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

static int copy_query_data(struct drm_i915_query_item *query_item,
			   const void *item_ptr, u32 item_length,
			   const void *data_ptr, u32 data_length)
{
	u32 total_length = item_length + data_length;

	if (GEM_WARN_ON(add_overflows(item_length, data_length)))
		return -EINVAL;

	if (query_item->length == 0)
		return total_length;

	if (query_item->length < total_length)
		return -EINVAL;

	if (!access_ok(VERIFY_WRITE, u64_to_user_ptr(query_item->data_ptr),
		       total_length))
		return -EFAULT;

	if (__copy_to_user(u64_to_user_ptr(query_item->data_ptr),
			   item_ptr, item_length))
		return -EFAULT;

	if (__copy_to_user(u64_to_user_ptr(query_item->data_ptr + item_length),
			   data_ptr, data_length))
		return -EFAULT;

	return total_length;
}

static int query_slice_info(struct drm_i915_private *dev_priv,
			    struct drm_i915_query_item *query_item)
{
	const struct sseu_dev_info *sseu = &INTEL_INFO(dev_priv)->sseu;
	struct drm_i915_query_slice_info slice_info;

	if (query_item->flags != 0)
		return -EINVAL;

	if (sseu->max_slices == 0)
		return -ENODEV;

	/*
	 * If we ever change the internal slice mask data type, we'll need to
	 * update this function.
	 */
	BUILD_BUG_ON(sizeof(u8) != sizeof(sseu->slice_mask));

	memset(&slice_info, 0, sizeof(slice_info));
	slice_info.max_slices = sseu->max_slices;

	return copy_query_data(query_item, &slice_info, sizeof(slice_info),
			       &sseu->slice_mask, sizeof(sseu->slice_mask));
}

static int query_subslice_info(struct drm_i915_private *dev_priv,
			       struct drm_i915_query_item *query_item)
{
	const struct sseu_dev_info *sseu = &INTEL_INFO(dev_priv)->sseu;
	struct drm_i915_query_subslice_info subslice_info;
	u32 data_length;

	if (query_item->flags != 0)
		return -EINVAL;

	if (sseu->max_slices == 0)
		return -ENODEV;

	memset(&subslice_info, 0, sizeof(subslice_info));
	subslice_info.max_slices = sseu->max_slices;
	subslice_info.max_subslices = sseu->max_subslices;

	data_length = subslice_info.max_slices *
		DIV_ROUND_UP(subslice_info.max_subslices,
			     sizeof(sseu->subslice_mask[0]) * BITS_PER_BYTE);

	return copy_query_data(query_item,
			       &subslice_info, sizeof(subslice_info),
			       sseu->subslice_mask, data_length);
}

static int query_eu_info(struct drm_i915_private *dev_priv,
			 struct drm_i915_query_item *query_item)
{
	const struct sseu_dev_info *sseu = &INTEL_INFO(dev_priv)->sseu;
	struct drm_i915_query_eu_info eu_info;
	u32 data_length;

	if (query_item->flags != 0)
		return -EINVAL;

	if (sseu->max_slices == 0)
		return -ENODEV;

	memset(&eu_info, 0, sizeof(eu_info));
	eu_info.max_slices = sseu->max_slices;
	eu_info.max_subslices = sseu->max_subslices;
	eu_info.max_eus_per_subslice = sseu->max_eus_per_subslice;

	data_length = eu_info.max_slices * eu_info.max_subslices *
		DIV_ROUND_UP(eu_info.max_eus_per_subslice, BITS_PER_BYTE);

	return copy_query_data(query_item,
			       &eu_info, sizeof(eu_info),
			       sseu->eu_mask, data_length);
}

static int (* const i915_query_funcs[])(struct drm_i915_private *dev_priv,
					struct drm_i915_query_item *query_item) = {
	query_slice_info,
	query_subslice_info,
	query_eu_info,
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
