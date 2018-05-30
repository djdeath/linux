/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright © 2018 Intel Corporation
 */

#include <linux/nospec.h>

#include "i915_drv.h"
#include "i915_query.h"
#include <uapi/drm/i915_drm.h>

static int query_topology_info(struct drm_i915_private *dev_priv,
			       struct drm_i915_query_item *query_item)
{
	const struct sseu_dev_info *sseu = &INTEL_INFO(dev_priv)->sseu;
	struct drm_i915_query_topology_info topo;
	u32 slice_length, subslice_length, eu_length, total_length;

	if (query_item->flags != 0)
		return -EINVAL;

	if (sseu->max_slices == 0)
		return -ENODEV;

	BUILD_BUG_ON(sizeof(u8) != sizeof(sseu->slice_mask));

	slice_length = sizeof(sseu->slice_mask);
	subslice_length = sseu->max_slices *
		DIV_ROUND_UP(sseu->max_subslices,
			     sizeof(sseu->subslice_mask[0]) * BITS_PER_BYTE);
	eu_length = sseu->max_slices * sseu->max_subslices *
		DIV_ROUND_UP(sseu->max_eus_per_subslice, BITS_PER_BYTE);

	total_length = sizeof(topo) + slice_length + subslice_length + eu_length;

	if (query_item->length == 0)
		return total_length;

	if (query_item->length < total_length)
		return -EINVAL;

	if (copy_from_user(&topo, u64_to_user_ptr(query_item->data_ptr),
			   sizeof(topo)))
		return -EFAULT;

	if (topo.flags != 0)
		return -EINVAL;

	if (!access_ok(VERIFY_WRITE, u64_to_user_ptr(query_item->data_ptr),
		       total_length))
		return -EFAULT;

	memset(&topo, 0, sizeof(topo));
	topo.max_slices = sseu->max_slices;
	topo.max_subslices = sseu->max_subslices;
	topo.max_eus_per_subslice = sseu->max_eus_per_subslice;

	topo.subslice_offset = slice_length;
	topo.subslice_stride = DIV_ROUND_UP(sseu->max_subslices, BITS_PER_BYTE);
	topo.eu_offset = slice_length + subslice_length;
	topo.eu_stride =
		DIV_ROUND_UP(sseu->max_eus_per_subslice, BITS_PER_BYTE);

	if (__copy_to_user(u64_to_user_ptr(query_item->data_ptr),
			   &topo, sizeof(topo)))
		return -EFAULT;

	if (__copy_to_user(u64_to_user_ptr(query_item->data_ptr + sizeof(topo)),
			   &sseu->slice_mask, slice_length))
		return -EFAULT;

	if (__copy_to_user(u64_to_user_ptr(query_item->data_ptr +
					   sizeof(topo) + slice_length),
			   sseu->subslice_mask, subslice_length))
		return -EFAULT;

	if (__copy_to_user(u64_to_user_ptr(query_item->data_ptr +
					   sizeof(topo) +
					   slice_length + subslice_length),
			   sseu->eu_mask, eu_length))
		return -EFAULT;

	return total_length;
}

static int can_copy_perf_config_registers_or_number(u32 user_n_regs,
						    u64 user_regs_ptr,
						    u32 kernel_n_regs)
{
	/*
	 * We'll just put the number of registers, and won't copy the
	 * register.
	 */
	if (user_n_regs == 0)
		return 0;

	if (user_n_regs < kernel_n_regs)
		return -EINVAL;

	if (!access_ok(VERIFY_WRITE, user_regs_ptr,
		       2 * sizeof(u32) * kernel_n_regs))
		return -EFAULT;

	return 0;
}

static int copy_perf_config_registers_or_number(const struct i915_oa_reg *kernel_regs,
						u32 kernel_n_regs,
						u64 user_regs_ptr,
						u32 *user_n_regs)
{
	u32 r;

	if (*user_n_regs == 0) {
		*user_n_regs = kernel_n_regs;
		return 0;
	}

	*user_n_regs = kernel_n_regs;

	for (r = 0; r < kernel_n_regs; r++) {
		u32 __user *user_reg_ptr =
			u64_to_user_ptr(user_regs_ptr + sizeof(u32) * r * 2);
		u32 __user *user_val_ptr =
			u64_to_user_ptr(user_regs_ptr + sizeof(u32) * r * 2 +
					sizeof(u32));
		int ret;

		ret = __put_user(i915_mmio_reg_offset(kernel_regs[r].addr),
				 user_reg_ptr);
		if (ret)
			return -EFAULT;

		ret = __put_user(kernel_regs[r].value, user_val_ptr);
		if (ret)
			return -EFAULT;
	}

	return 0;
}

static int query_perf_config_data(struct drm_i915_private *i915,
				  struct drm_i915_query_item *query_item)
{
	struct drm_i915_query_perf_config __user *user_query_config_ptr =
		u64_to_user_ptr(query_item->data_ptr);
	struct drm_i915_perf_oa_config __user *user_config_ptr =
		u64_to_user_ptr(query_item->data_ptr +
				sizeof(struct drm_i915_query_perf_config));
	struct drm_i915_perf_oa_config user_config;
	struct i915_oa_config *oa_config;
	u64 config_id, flags;
	u32 total_size;
	int ret;

	if (!i915->perf.initialized)
		return -ENODEV;

	total_size = sizeof(struct drm_i915_query_perf_config) +
		sizeof(struct drm_i915_perf_oa_config);

	if (query_item->length == 0)
		return total_size;

	if (query_item->length < total_size)
		return -EINVAL;

	if (!access_ok(VERIFY_WRITE, user_query_config_ptr, total_size))
		return -EFAULT;

	if (__get_user(flags, &user_query_config_ptr->flags))
		return -EFAULT;

	if (flags != 0)
		return -EINVAL;

	if (__get_user(config_id, &user_query_config_ptr->config))
		return -EFAULT;

	ret = mutex_lock_interruptible(&i915->perf.metrics_lock);
	if (ret)
		return ret;

	if (config_id == 1) {
		oa_config = &i915->perf.oa.test_config;
	} else {
		oa_config = idr_find(&i915->perf.metrics_idr, config_id);
		if (!oa_config) {
			ret = -ENOENT;
			goto out;
		}
	}

	if (__copy_from_user(&user_config, user_config_ptr,
			     sizeof(user_config))) {
		ret = -EFAULT;
		goto out;
	}

	ret = can_copy_perf_config_registers_or_number(user_config.n_boolean_regs,
						       user_config.boolean_regs_ptr,
						       oa_config->b_counter_regs_len);
	if (ret)
		goto out;

	ret = can_copy_perf_config_registers_or_number(user_config.n_flex_regs,
						       user_config.flex_regs_ptr,
						       oa_config->flex_regs_len);
	if (ret)
		goto out;

	ret = can_copy_perf_config_registers_or_number(user_config.n_mux_regs,
						       user_config.mux_regs_ptr,
						       oa_config->mux_regs_len);
	if (ret)
		goto out;

	ret = copy_perf_config_registers_or_number(oa_config->b_counter_regs,
						   oa_config->b_counter_regs_len,
						   user_config.boolean_regs_ptr,
						   &user_config.n_boolean_regs);
	if (ret)
		goto out;

	ret = copy_perf_config_registers_or_number(oa_config->flex_regs,
						   oa_config->flex_regs_len,
						   user_config.flex_regs_ptr,
						   &user_config.n_flex_regs);
	if (ret)
		goto out;

	ret = copy_perf_config_registers_or_number(oa_config->mux_regs,
						   oa_config->mux_regs_len,
						   user_config.mux_regs_ptr,
						   &user_config.n_mux_regs);
	if (ret)
		goto out;

	memcpy(user_config.uuid, oa_config->uuid, sizeof(user_config.uuid));

	if (__copy_to_user(user_config_ptr, &user_config,
			   sizeof(user_config))) {
		ret = -EFAULT;
		goto out;
	}

	ret = total_size;

out:
	mutex_unlock(&i915->perf.metrics_lock);
	return ret;
}

static int query_perf_config_list(struct drm_i915_private *i915,
				  struct drm_i915_query_item *query_item)
{
	struct drm_i915_query_perf_config __user *user_query_config_ptr =
		u64_to_user_ptr(query_item->data_ptr);
	struct i915_oa_config *oa_config;
	u64 n_configs, flags;
	u32 total_size;
	int ret, id;

	if (!i915->perf.initialized)
		return -ENODEV;

	/* Count the default test configuration */
	n_configs = i915->perf.n_metrics + 1;
	total_size = sizeof(struct drm_i915_query_perf_config) +
		sizeof(u64) * n_configs;

	if (query_item->length == 0) {
		ret = total_size;
		goto out;
	}

	if (query_item->length < total_size) {
		ret = -EINVAL;
		goto out;
	}

	if (!access_ok(VERIFY_WRITE, user_query_config_ptr, total_size)) {
		ret = -EFAULT;
		goto out;
	}

	if (__get_user(flags, &user_query_config_ptr->flags)) {
		ret = -EFAULT;
		goto out;
	}

	if (flags != 0) {
		ret = -EINVAL;
		goto out;
	}

	if (__put_user(n_configs, &user_query_config_ptr->config)) {
		ret = -EFAULT;
		goto out;
	}

	if (__put_user((u64) 1ULL, &user_query_config_ptr->data[0])) {
		ret = -EFAULT;
		goto out;
	}

	ret = mutex_lock_interruptible(&i915->perf.metrics_lock);
	if (ret)
		return ret;

	n_configs = 1;
	idr_for_each_entry(&i915->perf.metrics_idr, oa_config, id) {
		if (__put_user((u64) id,
			       &user_query_config_ptr->data[0] +
			       n_configs * sizeof(u64))) {
			ret = -EFAULT;
			goto out;
		}
		n_configs++;
	}

	ret = total_size;

out:
	mutex_unlock(&i915->perf.metrics_lock);
	return ret;
}

static int query_perf_config(struct drm_i915_private *i915,
			     struct drm_i915_query_item *query_item)
{
	if (query_item->flags == DRM_I915_QUERY_PERF_CONFIG_LIST)
		return query_perf_config_list(i915, query_item);
	else if (query_item->flags == DRM_I915_QUERY_PERF_CONFIG_DATA)
		return query_perf_config_data(i915, query_item);

	return -EINVAL;
}


static int (* const i915_query_funcs[])(struct drm_i915_private *dev_priv,
					struct drm_i915_query_item *query_item) = {
	query_topology_info,
	query_perf_config,
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
		unsigned long func_idx;
		int ret;

		if (copy_from_user(&item, user_item_ptr, sizeof(item)))
			return -EFAULT;

		if (item.query_id == 0)
			return -EINVAL;

		if (overflows_type(item.query_id - 1, unsigned long))
			return -EINVAL;

		func_idx = item.query_id - 1;

		ret = -EINVAL;
		if (func_idx < ARRAY_SIZE(i915_query_funcs)) {
			func_idx = array_index_nospec(func_idx,
						      ARRAY_SIZE(i915_query_funcs));
			ret = i915_query_funcs[func_idx](dev_priv, &item);
		}

		/* Only write the length back to userspace if they differ. */
		if (ret != item.length && put_user(ret, &user_item_ptr->length))
			return -EFAULT;
	}

	return 0;
}
