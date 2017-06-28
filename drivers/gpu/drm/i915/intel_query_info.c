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

static u8 user_class_map[I915_ENGINE_CLASS_MAX] = {
	[I915_ENGINE_CLASS_OTHER] = OTHER_CLASS,
	[I915_ENGINE_CLASS_RENDER] = RENDER_CLASS,
	[I915_ENGINE_CLASS_COPY] = COPY_ENGINE_CLASS,
	[I915_ENGINE_CLASS_VIDEO] = VIDEO_DECODE_CLASS,
	[I915_ENGINE_CLASS_VIDEO_ENHANCE] = VIDEO_ENHANCEMENT_CLASS,
};

static int query_info_engine(struct drm_i915_private *dev_priv,
			     struct drm_i915_query_info *args)
{
	struct drm_i915_engine_info __user *user_info =
		u64_to_user_ptr(args->info_ptr);
	struct intel_engine_cs *engine;
	enum intel_engine_id id;
	u8 num_engines, class;
	u32 info_size;

	switch (args->query_params[0]) {
	case I915_ENGINE_CLASS_OTHER:
	case I915_ENGINE_CLASS_RENDER:
	case I915_ENGINE_CLASS_COPY:
	case I915_ENGINE_CLASS_VIDEO:
	case I915_ENGINE_CLASS_VIDEO_ENHANCE:
		class = user_class_map[args->query_params[0]];
		break;
	case I915_ENGINE_CLASS_MAX:
	default:
		return -EINVAL;
	};

	num_engines = 0;
	for_each_engine(engine, dev_priv, id) {
		if (class != engine->class)
			continue;

		num_engines++;
	}

	info_size = sizeof(struct drm_i915_engine_info) * num_engines;
	if (args->info_ptr_len == 0) {
		args->info_ptr_len = info_size;
		return 0;
	}

	if (args->info_ptr_len < info_size)
		return -EINVAL;

	for_each_engine(engine, dev_priv, id) {
		struct drm_i915_engine_info info;
		int ret;

		if (class != engine->class)
			continue;

		memset(&info, 0, sizeof(info));
		info.instance = engine->instance;
		if (INTEL_GEN(dev_priv) >= 8 && id == VCS)
			info.info = I915_VCS_HAS_HEVC;

		ret = copy_to_user(user_info++, &info, sizeof(info));
		if (ret)
			return -EFAULT;
	}

	return 0;
}


int i915_query_info_ioctl(struct drm_device *dev, void *data,
			  struct drm_file *file)
{
	struct drm_i915_private *dev_priv = to_i915(dev);
	struct drm_i915_query_info *args = data;

	/* Currently supported version of this API. */
	if (args->version == 0) {
		args->version = 1;
		return 0;
	}

	if (args->version != 1)
		return -EINVAL;

	switch (args->query) {
	case I915_QUERY_INFO_ENGINE:
		return query_info_engine(dev_priv, args);
	default:
		return -EINVAL;
	}
}
