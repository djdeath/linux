/*
 * Copyright © 2017 Red Hat
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
 * Authors:
 *
 */
#ifndef __DRM_SYNCOBJ_H__
#define __DRM_SYNCOBJ_H__

#include <linux/dma-fence.h>

struct drm_file;
struct drm_syncobj;

/**
 * struct drm_syncobj_point - sync object point.
 *
 * This structure defines a generic sync object which wraps a &dma_fence. A
 * binary syncobj contains a single @drm_syncobj_point, while a timeline
 * syncobj will contain multiple.
 */
struct drm_syncobj_point {
	/**
	 * @syncobj: A reference back to the syncobj containing this point.
	 */
	struct drm_syncobj *syncobj;
	/**
	 * @fence: A fence associated with this syncobj point. This fence is
	 * never signaled by the syncobj.
	 */
	struct dma_fence *fence;
	/**
	 * @fence_cb: A callback to be called when &fence is signaled.
	 */
	struct dma_fence_cb fence_cb;
	/**
	 * @link: linked list node in the list of points.
	 */
	struct list_head node;
	/**
	 * @value: Value of this point
	 */
	u64 value;
	/**
	 * @cb_list: List of callbacks to call when &fence gets replaced.
	 */
	struct list_head cb_list;
};

/**
 * struct drm_syncobj - sync object.
 *
 * This structure defines a generic sync object which wraps 2 types of sync
 * objects :
 *
 *   - binary: a syncobj that can be either signaled on unsignaled.
 *
 *   - timeline: a syncobj associated with a &u64 payload, that can be waited
 *     on at a particular value of the payload. Waiters are signaled in the
 *     order of the payload value.
 *
 */
struct drm_syncobj {
	/**
	 * @refcount: Reference count of this object.
	 */
	struct kref refcount;
	/**
	 * @type: Type of sync object.
	 */
	enum {
		DRM_SYNCOBJ_TYPE_BINARY,
		DRM_SYNCOBJ_TYPE_TIMELINE,
	} type;
	union {
		/**
		 * @binary: A container of the fields associated with a binary
		 * syncobj.
		 */
		struct drm_syncobj_point binary;
		/**
		 * @timeline: A container of the fields associated with a
		 * timeline syncobj.
		 */
		struct {
			/**
			 * @points: List of &drm_syncobj_point not yet
			 * signaled.
			 */
			struct list_head points;
			/**
			 * @value: Current value of the timeline.
			 */
			u64 value;
			/**
			 * @context: Context of the fences allocated with this
			 * syncobj.
			 */
			u64 context;
		} timeline;
	};
	/**
	 * @lock: Protects &binary and &timeline.
	 */
	spinlock_t lock;
	/**
	 * @file: A file backing for this syncobj.
	 */
	struct file *file;
};

/**
 * struct drm_syncobj_array_item - sync object reference at a particular point
 *
 * This structure is used a container to describe a reference to a syncobj at
 * a particular point. An array of this structure is used to either give a
 * list of syncobj to wait or signal at a specific point.
 */
struct drm_syncobj_array_item {
	/**
	 * @syncobj: A syncobj, this pointer has a reference on the @syncobj
	 * and must be properly release using drm_syncobj_array_free().
	 */
	struct drm_syncobj *syncobj;
	/**
	 * @value: A value to signal or wait on.
	 */
	u64 value;
};

void drm_syncobj_free(struct kref *kref);

/**
 * drm_syncobj_get - acquire a syncobj reference
 * @obj: sync object
 *
 * This acquires an additional reference to @obj. It is illegal to call this
 * without already holding a reference. No locks required.
 */
static inline void
drm_syncobj_get(struct drm_syncobj *obj)
{
	kref_get(&obj->refcount);
}

/**
 * drm_syncobj_put - release a reference to a sync object.
 * @obj: sync object.
 */
static inline void
drm_syncobj_put(struct drm_syncobj *obj)
{
	kref_put(&obj->refcount, drm_syncobj_free);
}

/**
 * drm_syncobj_point_valid - verify whether a point is valid for a given
 * syncobj
 *
 * @obj: sync object.
 * @point: timeline point
 *
 * This is a useful utility function for userspace input validation.
 */
static inline bool
drm_syncobj_point_valid(struct drm_syncobj *obj, u64 point)
{
	if (obj->type == DRM_SYNCOBJ_TYPE_BINARY)
		return point == 0;
	else
		return point != 0;
}

struct drm_syncobj *drm_syncobj_find(struct drm_file *file_private,
				     u32 handle);
int drm_syncobj_replace_fence(struct drm_syncobj *syncobj, u64 point,
			      struct dma_fence *fence);
int drm_syncobj_find_fence(struct drm_file *file_private,
			   u32 handle, u64 point, u64 flags,
			   struct dma_fence **fence);
int drm_syncobj_fence_get(struct drm_syncobj *syncobj, u64 point,
			  struct dma_fence **fence);
void drm_syncobj_free(struct kref *kref);
int drm_syncobj_create(struct drm_syncobj **out_syncobj, uint32_t flags,
		       struct dma_fence *fence);
int drm_syncobj_get_handle(struct drm_file *file_private,
			   struct drm_syncobj *syncobj, u32 *handle);
int drm_syncobj_get_fd(struct drm_syncobj *syncobj, int *p_fd);

struct drm_syncobj_array_item *
drm_syncobj_array_from_user(struct drm_file *file_private, bool use_items,
			    void __user *data, u32 count);
void drm_syncobj_array_free(struct drm_syncobj_array_item *array, u32 count_items);

#endif
