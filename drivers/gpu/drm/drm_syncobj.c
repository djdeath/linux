/*
 * Copyright 2017 Red Hat
 * Parts ported from amdgpu (fence wait code).
 * Copyright 2016 Advanced Micro Devices, Inc.
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

/**
 * DOC: Overview
 *
 * DRM synchronisation objects (syncobj, see struct &drm_syncobj) are
 * persistent objects that contain an optional fence. The fence can be updated
 * with a new fence, or be NULL.
 *
 * syncobj's can be waited upon, where it will wait for the underlying
 * fence.
 *
 * syncobj's can be export to fd's and back, these fd's are opaque and
 * have no other use case, except passing the syncobj between processes.
 *
 * Their primary use-case is to implement Vulkan fences and semaphores.
 *
 * syncobj have a kref reference count, but also have an optional file.
 * The file is only created once the syncobj is exported.
 * The file takes a reference on the kref.
 */

#include <drm/drmP.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/anon_inodes.h>
#include <linux/sync_file.h>
#include <linux/sched/signal.h>

#include "drm_internal.h"
#include <drm/drm_syncobj.h>

struct syncobj_wait_entry {
	struct list_head node;
	struct task_struct *task;
	struct dma_fence *fence;
	struct dma_fence_cb fence_cb;
};

static void syncobj_wait_syncobj_func(struct drm_syncobj_point *pt,
				      struct syncobj_wait_entry *wait);

static void
drm_syncobj_point_init(struct drm_syncobj_point *pt,
		       struct drm_syncobj *syncobj, u64 value)
{
	pt->syncobj = syncobj;
	pt->value = value;
	pt->fence = NULL;
	INIT_LIST_HEAD(&pt->cb_list);
}

static void
drm_syncobj_point_signal(struct drm_syncobj_point *pt)
{
	struct syncobj_wait_entry *cur, *tmp;

	if (pt->fence) {
		dma_fence_remove_callback(pt->fence, &pt->fence_cb);
		dma_fence_put(pt->fence);
		pt->fence = NULL;
	}

	list_for_each_entry_safe(cur, tmp, &pt->cb_list, node) {
		list_del_init(&cur->node);
		syncobj_wait_syncobj_func(pt, cur);
	}
}

static void
drm_syncobj_point_free(struct drm_syncobj_point *pt)
{
	drm_syncobj_point_signal(pt);

	list_del(&pt->node);
	kfree(pt);
}

static void
drm_syncobj_points_free(struct list_head *list)
{
	struct drm_syncobj_point *cur, *tmp;

	list_for_each_entry_safe(cur, tmp, list, node)
		drm_syncobj_point_free(cur);
}

/**
 * drm_syncobj_signal_upto_locked - signal points of a timeline up to a given
 * point
 * @syncobj: syncobj containing points to signal
 * @value: maximum point value to signal (inclusive)
 * @signaled: list to which signaled points are to be added
 *
 * Lock of the syncobj must be held before calling this function and the lock
 * is transfered to this function.
 */
static void drm_syncobj_signal_upto_locked(struct drm_syncobj *syncobj,
					   u64 value,
					   struct list_head *signaled)
{
	struct drm_syncobj_point *cur, *tmp;

	/*
	 * Update timeline value first, this might be used in the signaling
	 * callbacks.
	 */
	syncobj->timeline.value = max(syncobj->timeline.value, value);

	list_for_each_entry_safe(cur, tmp, &syncobj->timeline.points, node) {
		if (cur->value > value)
			break;
		list_del(&cur->node);
		drm_syncobj_point_signal(cur);
		list_add_tail(&cur->node, signaled);
	}
}

static void drm_syncobj_point_fence_signaled(struct dma_fence *_fence,
					     struct dma_fence_cb *cb)
{
	struct drm_syncobj_point *pt = container_of(cb, typeof(*pt), fence_cb);
	struct drm_syncobj *syncobj = pt->syncobj;
	struct list_head signaled_points;
	struct dma_fence *fence;

	INIT_LIST_HEAD(&signaled_points);

	spin_lock_nested(&syncobj->lock, SINGLE_DEPTH_NESTING);

	/*
	 * We can remove the fence right now because its callback will be
	 * removed by the caller.
	 */
	fence = pt->fence;
	pt->fence = NULL;

	drm_syncobj_signal_upto_locked(syncobj, pt->value, &signaled_points);

	spin_unlock(&syncobj->lock);

	/* Now destroy all the signaled points outside the syncobj's lock. */
	drm_syncobj_points_free(&signaled_points);

	dma_fence_put(fence);
}

/**
 * drm_syncobj_find - lookup and reference a sync object.
 * @file_private: drm file private pointer
 * @handle: sync object handle to lookup.
 *
 * Returns a reference to the syncobj pointed to by handle or NULL. The
 * reference must be released by calling drm_syncobj_put().
 */
struct drm_syncobj *drm_syncobj_find(struct drm_file *file_private,
				     u32 handle)
{
	struct drm_syncobj *syncobj;

	spin_lock(&file_private->syncobj_table_lock);

	/* Check if we currently have a reference on the object */
	syncobj = idr_find(&file_private->syncobj_idr, handle);
	if (syncobj)
		drm_syncobj_get(syncobj);

	spin_unlock(&file_private->syncobj_table_lock);

	return syncobj;
}
EXPORT_SYMBOL(drm_syncobj_find);

static struct drm_syncobj_point *
drm_syncobj_find_or_create_point_locked(struct drm_syncobj *syncobj, u64 point)
{
	struct drm_syncobj_point *cur, *tmp;
	struct drm_syncobj_point *pt;

	WARN_ON(syncobj->type != DRM_SYNCOBJ_TYPE_TIMELINE);

	if (point <= syncobj->timeline.value)
		return NULL;

	list_for_each_entry_safe(cur, tmp, &syncobj->timeline.points, node) {
		if (cur->value == point)
			return cur;
		if (cur->value > point) {
			pt = kzalloc(sizeof(*pt), GFP_KERNEL);
			if (pt == NULL)
				return ERR_PTR(-ENOMEM);

			drm_syncobj_point_init(pt, syncobj, point);
			list_add_tail(&pt->node, &cur->node);

			return pt;
		}
	}

	pt = kzalloc(sizeof(*pt), GFP_KERNEL);
	if (pt == NULL)
		return ERR_PTR(-ENOMEM);

	drm_syncobj_point_init(pt, syncobj, point);
	list_add_tail(&pt->node, &syncobj->timeline.points);

	return pt;
}

static void drm_syncobj_fence_add_wait(struct drm_syncobj *syncobj, u64 value,
				       struct syncobj_wait_entry *wait)
{
	struct drm_syncobj_point *pt;

	if (wait->fence)
		return;

	spin_lock(&syncobj->lock);

	if (syncobj->type == DRM_SYNCOBJ_TYPE_BINARY) {
		pt = &syncobj->binary;

		/* We've already tried once to get a fence and failed. Now
		 * that we have the lock, try one more time just to be sure we
		 * don't add a callback when a fence has already been set.
		 */
		if (pt->fence)
			wait->fence = dma_fence_get(pt->fence);
		else
			list_add_tail(&wait->node, &pt->cb_list);
	} else {
		if (value <= syncobj->timeline.value) {
			wait->fence = dma_fence_get_stub();
		} else {
			/*
			 * The points should have been created by an earlier
			 * call to drm_syncobj_fence_get. An error is not
			 * expected.
			 */
			pt = drm_syncobj_find_or_create_point_locked(syncobj,
								     value);
			WARN_ON(IS_ERR(pt) || pt == NULL);

			if (pt->fence)
				wait->fence = dma_fence_get(pt->fence);
			else
				list_add_tail(&wait->node, &pt->cb_list);
		}
	}

	spin_unlock(&syncobj->lock);
}

static void drm_syncobj_remove_wait(struct drm_syncobj *syncobj,
				    struct syncobj_wait_entry *wait)
{
	if (!wait->node.next)
		return;

	spin_lock(&syncobj->lock);
	list_del_init(&wait->node);
	spin_unlock(&syncobj->lock);
}

/**
 * drm_syncobj_replace_fence - replace fence in a sync object.
 * @syncobj: Sync object to replace fence in
 * @point: point to replace fence in
 * @new_fence: fence to install in sync file.
 *
 * This replaces the fence on a sync object.
 */
int drm_syncobj_replace_fence(struct drm_syncobj *syncobj,
			      u64 point,
			      struct dma_fence *new_fence)
{
	struct syncobj_wait_entry *cur, *tmp;
	struct dma_fence *old_fence = NULL;
	struct list_head signaled_points;
	struct drm_syncobj_point *pt;
	int ret = 0;

	INIT_LIST_HEAD(&signaled_points);

	/* We allow nested lock because adding the callback might fire it. */
	spin_lock_nested(&syncobj->lock, SINGLE_DEPTH_NESTING);

	if (syncobj->type == DRM_SYNCOBJ_TYPE_BINARY) {
		pt = &syncobj->binary;
	} else {
		/* Replacing a point already signaled is a no-op. */
		if (point <= syncobj->timeline.value)
			goto unlock;

		pt = drm_syncobj_find_or_create_point_locked(syncobj, point);
		if (IS_ERR(pt)) {
			ret = PTR_ERR(pt);
			goto unlock;
		}
	}

	old_fence = pt->fence;
	pt->fence = dma_fence_get(new_fence);

	/* Signal all the waiters that the fence has materialized. */
	if (new_fence != old_fence) {
		if (syncobj->type == DRM_SYNCOBJ_TYPE_TIMELINE) {
			/*
			 * For timeline syncobjs we need to update the
			 * callbacks on the fence.
			 */
			if (old_fence) {
				dma_fence_remove_callback(old_fence,
							  &pt->fence_cb);
			}

			if (new_fence) {
				ret = dma_fence_add_callback(
					new_fence, &pt->fence_cb,
					drm_syncobj_point_fence_signaled);
			}

			/*
			 * This means the installed fence is signaled, signal
			 * all previous points.
			 */
			if (ret == -ENOENT) {
				ret = 0;
				drm_syncobj_signal_upto_locked(
					syncobj, point, &signaled_points);
				/*
				 * dma_fence_add_callback may or may not call
				 * our callback, leading to the point being
				 * freed. So we just need to assume the point
				 * was freed here or we might crash below.
				 */
				pt = NULL;
			}
		}

		if (pt) {
			list_for_each_entry_safe(cur, tmp, &pt->cb_list, node) {
				list_del_init(&cur->node);
				syncobj_wait_syncobj_func(pt, cur);
			}
		}
	}

unlock:
	spin_unlock(&syncobj->lock);

	drm_syncobj_points_free(&signaled_points);

	dma_fence_put(old_fence);

	return ret;
}
EXPORT_SYMBOL(drm_syncobj_replace_fence);

/**
 * drm_syncobj_assign_null_handle - assign a stub fence to the sync object
 * @syncobj: sync object to assign the fence on
 *
 * Assign a already signaled stub fence to the sync object.
 */
static void drm_syncobj_assign_null_handle(struct drm_syncobj *syncobj)
{
	struct dma_fence *fence = dma_fence_get_stub();

	drm_syncobj_replace_fence(syncobj, 0, fence);
	dma_fence_put(fence);
}

static void
drm_syncobj_signal(struct drm_syncobj *syncobj, u64 point)
{
	if (syncobj->type == DRM_SYNCOBJ_TYPE_BINARY)
		drm_syncobj_assign_null_handle(syncobj);
	else {
		struct list_head signaled_points;

		INIT_LIST_HEAD(&signaled_points);

		spin_lock(&syncobj->lock);
		drm_syncobj_signal_upto_locked(
			syncobj, point, &signaled_points);
		spin_unlock(&syncobj->lock);

		drm_syncobj_points_free(&signaled_points);
	}
}

/**
 * drm_syncobj_fence_get - get a reference to a fence in a timeline sync
 * object at a given point
 * @syncobj: sync object
 * @point: point get the fence from
 * @fence: fence to store
 *
 * This acquires additional reference to &drm_syncobj.fence contained in @obj,
 * if not NULL. It is illegal to call this without already holding a reference.
 * No locks required.
 *
 * Returns:
 * Either the fence of @obj or NULL if there's none.
 */
int drm_syncobj_fence_get(struct drm_syncobj *syncobj, u64 point,
			  struct dma_fence **fence)
{
	int ret = 0;

	if (!drm_syncobj_point_valid(syncobj, point))
		return -EINVAL;

	if (syncobj->type == DRM_SYNCOBJ_TYPE_BINARY) {
		*fence = dma_fence_get(syncobj->binary.fence);
	} else {
		spin_lock(&syncobj->lock);
		if (point <= syncobj->timeline.value) {
			*fence = dma_fence_get_stub();
		} else {
			struct drm_syncobj_point *pt =
				drm_syncobj_find_or_create_point_locked(syncobj,
									point);

			if (IS_ERR(pt))
				ret = PTR_ERR(pt);
			else
				*fence = dma_fence_get(pt->fence);
		}
		spin_unlock(&syncobj->lock);
	}

	return ret;
}
EXPORT_SYMBOL(drm_syncobj_fence_get);

/**
 * drm_syncobj_find_fence - lookup and reference the fence in a sync object
 * @file_private: drm file private pointer
 * @handle: sync object handle to lookup.
 * @point: timeline point
 * @flags: DRM_SYNCOBJ_WAIT_FLAGS_WAIT_FOR_SUBMIT or not
 * @fence: out parameter for the fence
 *
 * This is just a convenience function that combines drm_syncobj_find() and
 * drm_syncobj_fence_get().
 *
 * Returns 0 on success or a negative error value on failure. On success @fence
 * contains a reference to the fence, which must be released by calling
 * dma_fence_put().
 */
int drm_syncobj_find_fence(struct drm_file *file_private,
			   u32 handle, u64 point, u64 flags,
			   struct dma_fence **fence)
{
	struct drm_syncobj *syncobj = drm_syncobj_find(file_private, handle);
	int ret = 0;

	if (!syncobj)
		return -ENOENT;

	ret = drm_syncobj_fence_get(syncobj, point, fence);
	drm_syncobj_put(syncobj);

	return ret;
}
EXPORT_SYMBOL(drm_syncobj_find_fence);

/**
 * drm_syncobj_free - free a sync object.
 * @kref: kref to free.
 *
 * Only to be called from kref_put in drm_syncobj_put.
 */
void drm_syncobj_free(struct kref *kref)
{
	struct drm_syncobj *syncobj = container_of(kref,
						   struct drm_syncobj,
						   refcount);

	if (syncobj->type == DRM_SYNCOBJ_TYPE_BINARY) {
		drm_syncobj_replace_fence(syncobj, 0, NULL);
	} else {
		struct list_head points;

		INIT_LIST_HEAD(&points);
		/*
		 * The syncobj timeline can be destroyed at the same time that
		 * one of the dma_fence of one of the point fires.
		 *
		 * In order to avoid a deadlock when we try to remove the
		 * dma_fence callback (taking the fence's lock) and the
		 * callback (locked by the signaler) trying to lock the
		 * syncobj, we first lock the object and detacth all the
		 * points from the list without touching them. Then outside
		 * the syncobj's lock we destroy all the points. This is safe
		 * because the dma_fence callback will only find an empty list
		 * after it locked the syncobj and won't do anything. Freeing
		 * the points one by one outside is safe as well because we
		 * have to take the lock of the dma_fence before freeing the
		 * point, ensuring that all callbacks are finished or removed
		 * by the time we free the point.
		 */
		spin_lock(&syncobj->lock);
		syncobj->timeline.value = U64_MAX;
		if (!list_empty(&syncobj->timeline.points)) {
			list_bulk_move_tail(&points,
					    syncobj->timeline.points.next,
					    syncobj->timeline.points.prev);
		}
		spin_unlock(&syncobj->lock);

		drm_syncobj_points_free(&points);
	}
	kfree(syncobj);
}
EXPORT_SYMBOL(drm_syncobj_free);

/**
 * drm_syncobj_create - create a new syncobj
 * @out_syncobj: returned syncobj
 * @flags: DRM_SYNCOBJ_* flags
 * @fence: if non-NULL, the syncobj will represent this fence
 *
 * This is the first function to create a sync object. After creating, drivers
 * probably want to make it available to userspace, either through
 * drm_syncobj_get_handle() or drm_syncobj_get_fd().
 *
 * Returns 0 on success or a negative error value on failure.
 */
int drm_syncobj_create(struct drm_syncobj **out_syncobj, uint32_t flags,
		       struct dma_fence *fence)
{
	struct drm_syncobj *syncobj;

	if ((flags & DRM_SYNCOBJ_CREATE_TIMELINE) && fence)
		return -EINVAL;

	syncobj = kzalloc(sizeof(struct drm_syncobj), GFP_KERNEL);
	if (!syncobj)
		return -ENOMEM;

	kref_init(&syncobj->refcount);

	spin_lock_init(&syncobj->lock);

	if (flags & DRM_SYNCOBJ_CREATE_TIMELINE) {
		syncobj->type = DRM_SYNCOBJ_TYPE_TIMELINE;
		syncobj->timeline.context = dma_fence_context_alloc(1);
		INIT_LIST_HEAD(&syncobj->timeline.points);
	} else {
		syncobj->type = DRM_SYNCOBJ_TYPE_BINARY;
		drm_syncobj_point_init(&syncobj->binary, syncobj, 1);
		if (flags & DRM_SYNCOBJ_CREATE_SIGNALED)
			drm_syncobj_assign_null_handle(syncobj);
		if (fence)
			drm_syncobj_replace_fence(syncobj, 0, fence);
	}

	*out_syncobj = syncobj;
	return 0;
}
EXPORT_SYMBOL(drm_syncobj_create);

/**
 * drm_syncobj_get_handle - get a handle from a syncobj
 * @file_private: drm file private pointer
 * @syncobj: Sync object to export
 * @handle: out parameter with the new handle
 *
 * Exports a sync object created with drm_syncobj_create() as a handle on
 * @file_private to userspace.
 *
 * Returns 0 on success or a negative error value on failure.
 */
int drm_syncobj_get_handle(struct drm_file *file_private,
			   struct drm_syncobj *syncobj, u32 *handle)
{
	int ret;

	/* take a reference to put in the idr */
	drm_syncobj_get(syncobj);

	idr_preload(GFP_KERNEL);
	spin_lock(&file_private->syncobj_table_lock);
	ret = idr_alloc(&file_private->syncobj_idr, syncobj, 1, 0, GFP_NOWAIT);
	spin_unlock(&file_private->syncobj_table_lock);

	idr_preload_end();

	if (ret < 0) {
		drm_syncobj_put(syncobj);
		return ret;
	}

	*handle = ret;
	return 0;
}
EXPORT_SYMBOL(drm_syncobj_get_handle);

static int drm_syncobj_create_as_handle(struct drm_file *file_private,
					u32 *handle, uint32_t flags)
{
	int ret;
	struct drm_syncobj *syncobj;

	ret = drm_syncobj_create(&syncobj, flags, NULL);
	if (ret)
		return ret;

	ret = drm_syncobj_get_handle(file_private, syncobj, handle);
	drm_syncobj_put(syncobj);
	return ret;
}

static int drm_syncobj_destroy(struct drm_file *file_private,
			       u32 handle)
{
	struct drm_syncobj *syncobj;

	spin_lock(&file_private->syncobj_table_lock);
	syncobj = idr_remove(&file_private->syncobj_idr, handle);
	spin_unlock(&file_private->syncobj_table_lock);

	if (!syncobj)
		return -EINVAL;

	drm_syncobj_put(syncobj);
	return 0;
}

static int drm_syncobj_file_release(struct inode *inode, struct file *file)
{
	struct drm_syncobj *syncobj = file->private_data;

	drm_syncobj_put(syncobj);
	return 0;
}

static const struct file_operations drm_syncobj_file_fops = {
	.release = drm_syncobj_file_release,
};

/**
 * drm_syncobj_get_fd - get a file descriptor from a syncobj
 * @syncobj: Sync object to export
 * @p_fd: out parameter with the new file descriptor
 *
 * Exports a sync object created with drm_syncobj_create() as a file descriptor.
 *
 * Returns 0 on success or a negative error value on failure.
 */
int drm_syncobj_get_fd(struct drm_syncobj *syncobj, int *p_fd)
{
	struct file *file;
	int fd;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0)
		return fd;

	file = anon_inode_getfile("syncobj_file",
				  &drm_syncobj_file_fops,
				  syncobj, 0);
	if (IS_ERR(file)) {
		put_unused_fd(fd);
		return PTR_ERR(file);
	}

	drm_syncobj_get(syncobj);
	fd_install(fd, file);

	*p_fd = fd;
	return 0;
}
EXPORT_SYMBOL(drm_syncobj_get_fd);

static int drm_syncobj_handle_to_fd(struct drm_file *file_private,
				    u32 handle, int *p_fd)
{
	struct drm_syncobj *syncobj = drm_syncobj_find(file_private, handle);
	int ret;

	if (!syncobj)
		return -EINVAL;

	ret = drm_syncobj_get_fd(syncobj, p_fd);
	drm_syncobj_put(syncobj);
	return ret;
}

static int drm_syncobj_fd_to_handle(struct drm_file *file_private,
				    int fd, u32 *handle)
{
	struct drm_syncobj *syncobj;
	struct file *file;
	int ret;

	file = fget(fd);
	if (!file)
		return -EINVAL;

	if (file->f_op != &drm_syncobj_file_fops) {
		fput(file);
		return -EINVAL;
	}

	/* take a reference to put in the idr */
	syncobj = file->private_data;
	drm_syncobj_get(syncobj);

	idr_preload(GFP_KERNEL);
	spin_lock(&file_private->syncobj_table_lock);
	ret = idr_alloc(&file_private->syncobj_idr, syncobj, 1, 0, GFP_NOWAIT);
	spin_unlock(&file_private->syncobj_table_lock);
	idr_preload_end();

	if (ret > 0) {
		*handle = ret;
		ret = 0;
	} else
		drm_syncobj_put(syncobj);

	fput(file);
	return ret;
}

static int drm_syncobj_import_sync_file_fence(struct drm_file *file_private,
					      int fd, u32 handle, u64 point)
{
	struct dma_fence *fence = sync_file_get_fence(fd);
	struct drm_syncobj *syncobj;
	int ret;

	if (!fence)
		return -EINVAL;

	syncobj = drm_syncobj_find(file_private, handle);
	if (!syncobj) {
		dma_fence_put(fence);
		return -ENOENT;
	}

	if (drm_syncobj_point_valid(syncobj, point))
		ret = drm_syncobj_replace_fence(syncobj, point, fence);
	else
		ret = -EINVAL;
	dma_fence_put(fence);
	drm_syncobj_put(syncobj);
	return ret;
}

static int drm_syncobj_export_sync_file(struct drm_file *file_private,
					u32 handle, u64 point, int *p_fd)
{
	int ret;
	struct dma_fence *fence;
	struct sync_file *sync_file;
	int fd = get_unused_fd_flags(O_CLOEXEC);

	if (fd < 0)
		return fd;

	ret = drm_syncobj_find_fence(file_private, handle, point, 0, &fence);
	if (ret)
		goto err_put_fd;

	sync_file = sync_file_create(fence);

	dma_fence_put(fence);

	if (!sync_file) {
		ret = -EINVAL;
		goto err_put_fd;
	}

	fd_install(fd, sync_file->file);

	*p_fd = fd;
	return 0;
err_put_fd:
	put_unused_fd(fd);
	return ret;
}
/**
 * drm_syncobj_open - initalizes syncobj file-private structures at devnode open time
 * @file_private: drm file-private structure to set up
 *
 * Called at device open time, sets up the structure for handling refcounting
 * of sync objects.
 */
void
drm_syncobj_open(struct drm_file *file_private)
{
	idr_init_base(&file_private->syncobj_idr, 1);
	spin_lock_init(&file_private->syncobj_table_lock);
}

static int
drm_syncobj_release_handle(int id, void *ptr, void *data)
{
	struct drm_syncobj *syncobj = ptr;

	drm_syncobj_put(syncobj);
	return 0;
}

/**
 * drm_syncobj_release - release file-private sync object resources
 * @file_private: drm file-private structure to clean up
 *
 * Called at close time when the filp is going away.
 *
 * Releases any remaining references on objects by this filp.
 */
void
drm_syncobj_release(struct drm_file *file_private)
{
	idr_for_each(&file_private->syncobj_idr,
		     &drm_syncobj_release_handle, file_private);
	idr_destroy(&file_private->syncobj_idr);
}

int
drm_syncobj_create_ioctl(struct drm_device *dev, void *data,
			 struct drm_file *file_private)
{
	struct drm_syncobj_create *args = data;

	if (!drm_core_check_feature(dev, DRIVER_SYNCOBJ))
		return -EOPNOTSUPP;

	/* no valid flags yet */
	if (args->flags & ~(DRM_SYNCOBJ_CREATE_SIGNALED |
			    DRM_SYNCOBJ_CREATE_TIMELINE))
		return -EINVAL;

	if ((args->flags & DRM_SYNCOBJ_CREATE_TIMELINE) &&
	    !drm_core_check_feature(dev, DRIVER_SYNCOBJ_TIMELINE))
		return -EOPNOTSUPP;

	/* non sensical */
	if ((args->flags & DRM_SYNCOBJ_CREATE_TIMELINE) &&
	    (args->flags & DRM_SYNCOBJ_CREATE_SIGNALED))
		return -EINVAL;

	return drm_syncobj_create_as_handle(file_private,
					    &args->handle, args->flags);
}

int
drm_syncobj_destroy_ioctl(struct drm_device *dev, void *data,
			  struct drm_file *file_private)
{
	struct drm_syncobj_destroy *args = data;

	if (!drm_core_check_feature(dev, DRIVER_SYNCOBJ))
		return -EOPNOTSUPP;

	/* make sure padding is empty */
	if (args->pad)
		return -EINVAL;
	return drm_syncobj_destroy(file_private, args->handle);
}

int
drm_syncobj_handle_to_fd_ioctl(struct drm_device *dev, void *data,
				   struct drm_file *file_private)
{
	struct drm_syncobj_handle *args = data;

	if (!drm_core_check_feature(dev, DRIVER_SYNCOBJ))
		return -EOPNOTSUPP;

	if (args->pad)
		return -EINVAL;

	if (args->flags != 0 &&
	    args->flags != DRM_SYNCOBJ_HANDLE_TO_FD_FLAGS_EXPORT_SYNC_FILE)
		return -EINVAL;

	if (args->flags & DRM_SYNCOBJ_HANDLE_TO_FD_FLAGS_EXPORT_SYNC_FILE)
		return drm_syncobj_export_sync_file(file_private,
						    args->handle, 0,
						    &args->fd);

	return drm_syncobj_handle_to_fd(file_private, args->handle,
					&args->fd);
}

int
drm_syncobj_fd_to_handle_ioctl(struct drm_device *dev, void *data,
				   struct drm_file *file_private)
{
	struct drm_syncobj_handle *args = data;

	if (!drm_core_check_feature(dev, DRIVER_SYNCOBJ))
		return -EOPNOTSUPP;

	if (args->pad)
		return -EINVAL;

	if (args->flags != 0 &&
	    args->flags != DRM_SYNCOBJ_FD_TO_HANDLE_FLAGS_IMPORT_SYNC_FILE)
		return -EINVAL;

	if (args->flags & DRM_SYNCOBJ_FD_TO_HANDLE_FLAGS_IMPORT_SYNC_FILE)
		return drm_syncobj_import_sync_file_fence(file_private,
							  args->fd,
							  args->handle, 0);

	return drm_syncobj_fd_to_handle(file_private, args->fd,
					&args->handle);
}

int
drm_syncobj_handle_to_fd2_ioctl(struct drm_device *dev, void *data,
				   struct drm_file *file_private)
{
	struct drm_syncobj_handle2 *args = data;

	if (!drm_core_check_feature(dev, DRIVER_SYNCOBJ))
		return -EOPNOTSUPP;

	if (args->pad)
		return -EINVAL;

	if (args->flags != 0 &&
	    args->flags != DRM_SYNCOBJ_HANDLE_TO_FD_FLAGS_EXPORT_SYNC_FILE)
		return -EINVAL;

	if (args->flags & DRM_SYNCOBJ_HANDLE_TO_FD_FLAGS_EXPORT_SYNC_FILE)
		return drm_syncobj_export_sync_file(file_private,
						    args->handle, args->value,
						    &args->fd);

	return drm_syncobj_handle_to_fd(file_private, args->handle,
					&args->fd);
}

int
drm_syncobj_fd_to_handle2_ioctl(struct drm_device *dev, void *data,
				   struct drm_file *file_private)
{
	struct drm_syncobj_handle2 *args = data;

	if (!drm_core_check_feature(dev, DRIVER_SYNCOBJ))
		return -EOPNOTSUPP;

	if (args->pad)
		return -EINVAL;

	if (args->flags != 0 &&
	    args->flags != DRM_SYNCOBJ_FD_TO_HANDLE_FLAGS_IMPORT_SYNC_FILE)
		return -EINVAL;

	if (args->flags & DRM_SYNCOBJ_FD_TO_HANDLE_FLAGS_IMPORT_SYNC_FILE)
		return drm_syncobj_import_sync_file_fence(file_private,
							  args->fd,
							  args->handle,
							  args->value);

	return drm_syncobj_fd_to_handle(file_private, args->fd,
					&args->handle);
}

static void syncobj_wait_fence_func(struct dma_fence *fence,
				    struct dma_fence_cb *cb)
{
	struct syncobj_wait_entry *wait =
		container_of(cb, struct syncobj_wait_entry, fence_cb);

	wake_up_process(wait->task);
}

static void syncobj_wait_syncobj_func(struct drm_syncobj_point *pt,
				      struct syncobj_wait_entry *wait)
{
	/* This happens inside the syncobj lock */
	if (pt->syncobj->type == DRM_SYNCOBJ_TYPE_BINARY)
		wait->fence = dma_fence_get(pt->fence);
	else {
		wait->fence = pt->syncobj->timeline.value < pt->value ?
			dma_fence_get(pt->fence) : dma_fence_get_stub();
	}
	wake_up_process(wait->task);
}

static signed long
drm_syncobj_array_wait_timeout(struct drm_syncobj_array_item *array,
			       uint32_t count,
			       uint32_t flags,
			       signed long timeout,
			       uint32_t *idx)
{
	struct syncobj_wait_entry *entries;
	struct dma_fence *fence;
	uint32_t signaled_count, i;

	entries = kcalloc(count, sizeof(*entries), GFP_KERNEL);
	if (!entries)
		return -ENOMEM;

	/* Walk the list of sync objects and initialize entries.  We do
	 * this up-front so that we can properly return -EINVAL if there is
	 * a syncobj with a missing fence and then never have the chance of
	 * returning -EINVAL again.
	 */
	signaled_count = 0;
	for (i = 0; i < count; ++i) {
		int ret = drm_syncobj_fence_get(array[i].syncobj,
						array[i].value,
						&entries[i].fence);

		if (ret) {
			timeout = -EINVAL;
			goto cleanup_entries;
		}

		entries[i].task = current;

		if (!entries[i].fence) {
			if (flags & DRM_SYNCOBJ_WAIT_FLAGS_WAIT_FOR_SUBMIT) {
				continue;
			} else {
				timeout = -EINVAL;
				goto cleanup_entries;
			}
		}

		if (dma_fence_is_signaled(entries[i].fence)) {
			if (signaled_count == 0 && idx)
				*idx = i;
			signaled_count++;
		}
	}

	if (signaled_count == count ||
	    (signaled_count > 0 &&
	     !(flags & DRM_SYNCOBJ_WAIT_FLAGS_WAIT_ALL)))
		goto cleanup_entries;

	/* There's a very annoying laxness in the dma_fence API here, in
	 * that backends are not required to automatically report when a
	 * fence is signaled prior to fence->ops->enable_signaling() being
	 * called.  So here if we fail to match signaled_count, we need to
	 * fallthough and try a 0 timeout wait!
	 */

	if (flags & DRM_SYNCOBJ_WAIT_FLAGS_WAIT_FOR_SUBMIT) {
		for (i = 0; i < count; ++i) {
			drm_syncobj_fence_add_wait(array[i].syncobj,
						   array[i].value,
						   &entries[i]);
		}
	}

	do {
		set_current_state(TASK_INTERRUPTIBLE);

		signaled_count = 0;
		for (i = 0; i < count; ++i) {
			fence = entries[i].fence;
			if (!fence)
				continue;

			if (dma_fence_is_signaled(fence) ||
			    (!entries[i].fence_cb.func &&
			     dma_fence_add_callback(fence,
						    &entries[i].fence_cb,
						    syncobj_wait_fence_func))) {
				/* The fence has been signaled */
				if (flags & DRM_SYNCOBJ_WAIT_FLAGS_WAIT_ALL) {
					signaled_count++;
				} else {
					if (idx)
						*idx = i;
					goto done_waiting;
				}
			}
		}

		if (signaled_count == count)
			goto done_waiting;

		if (timeout == 0) {
			timeout = -ETIME;
			goto done_waiting;
		}

		if (signal_pending(current)) {
			timeout = -ERESTARTSYS;
			goto done_waiting;
		}

		timeout = schedule_timeout(timeout);
	} while (1);

done_waiting:
	__set_current_state(TASK_RUNNING);

cleanup_entries:
	for (i = 0; i < count; ++i) {
		drm_syncobj_remove_wait(array[i].syncobj, &entries[i]);
		if (entries[i].fence_cb.func)
			dma_fence_remove_callback(entries[i].fence,
						  &entries[i].fence_cb);
		dma_fence_put(entries[i].fence);
	}
	kfree(entries);

	return timeout;
}

/**
 * drm_timeout_abs_to_jiffies - calculate jiffies timeout from absolute value
 *
 * @timeout_nsec: timeout nsec component in ns, 0 for poll
 *
 * Calculate the timeout in jiffies from an absolute time in sec/nsec.
 */
static signed long drm_timeout_abs_to_jiffies(int64_t timeout_nsec)
{
	ktime_t abs_timeout, now;
	u64 timeout_ns, timeout_jiffies64;

	/* make 0 timeout means poll - absolute 0 doesn't seem valid */
	if (timeout_nsec == 0)
		return 0;

	abs_timeout = ns_to_ktime(timeout_nsec);
	now = ktime_get();

	if (!ktime_after(abs_timeout, now))
		return 0;

	timeout_ns = ktime_to_ns(ktime_sub(abs_timeout, now));

	timeout_jiffies64 = nsecs_to_jiffies64(timeout_ns);
	/*  clamp timeout to avoid infinite timeout */
	if (timeout_jiffies64 >= MAX_SCHEDULE_TIMEOUT - 1)
		return MAX_SCHEDULE_TIMEOUT - 1;

	return timeout_jiffies64 + 1;
}

static int drm_syncobj_array_wait(struct drm_device *dev,
				  struct drm_file *file_private,
				  struct drm_syncobj_wait *wait,
				  struct drm_syncobj_array_item *array)
{
	signed long timeout = drm_timeout_abs_to_jiffies(wait->timeout_nsec);
	uint32_t first = ~0;

	timeout = drm_syncobj_array_wait_timeout(array,
						 wait->count_handles,
						 wait->flags,
						 timeout, &first);
	if (timeout < 0)
		return timeout;

	wait->first_signaled = first;
	return 0;
}

void drm_syncobj_array_free(struct drm_syncobj_array_item *array,
			    uint32_t count_items)
{
	uint32_t i;

	for (i = 0; i < count_items; i++) {
		drm_syncobj_put(array[i].syncobj);
	}
	kfree(array);
}

static struct drm_syncobj_array_item *
drm_syncobj_array_from_handles(struct drm_file *file_private,
			       void __user *user_handles,
			       uint32_t count_handles)
{
	struct drm_syncobj_array_item *array;
	u32 i, *handles;
	int ret;

	handles = kmalloc_array(count_handles, sizeof(*handles), GFP_KERNEL);
	if (handles == NULL)
		return ERR_PTR(-ENOMEM);

	if (copy_from_user(handles, user_handles,
			   sizeof(*handles) * count_handles)) {
		ret = -EFAULT;
		goto err_free_handles;
	}

	array = kmalloc_array(count_handles, sizeof(*array), GFP_KERNEL);
	if (array == NULL) {
		ret = -ENOMEM;
		goto err_free_handles;
	}

	for (i = 0; i < count_handles; i++) {
		array[i].syncobj = drm_syncobj_find(file_private, handles[i]);
		if (!array[i].syncobj) {
			ret = -ENOENT;
			goto err_put_syncobjs;
		}
		if (array[i].syncobj->type == DRM_SYNCOBJ_TYPE_TIMELINE) {
			ret = -EINVAL;
			i++;
			goto err_put_syncobjs;
		}

		array[i].value = 0;
	}

	kfree(handles);

	return array;

err_put_syncobjs:
	drm_syncobj_array_free(array, i);

err_free_handles:
	kfree(handles);

	return ERR_PTR(ret);
}

static struct drm_syncobj_array_item *
drm_syncobj_array_from_items(struct drm_file *file_private,
			     void __user *user_items,
			     u32 count_items)
{
	struct drm_syncobj_array_item *array;
	struct drm_syncobj_item *items;
	int ret;
	u32 i;

	items = kmalloc_array(count_items, sizeof(*items), GFP_KERNEL);
	if (items == NULL)
		return ERR_PTR(-ENOMEM);

	if (copy_from_user(items, user_items,
			   sizeof(*items) * count_items)) {
		ret = -EFAULT;
		goto err_free_handles;
	}

	array = kmalloc_array(count_items, sizeof(*array), GFP_KERNEL);
	if (array == NULL) {
		ret = -ENOMEM;
		goto err_free_handles;
	}

	for (i = 0; i < count_items; i++) {
		array[i].syncobj = drm_syncobj_find(file_private, items[i].handle);
		if (!array[i].syncobj) {
			ret = -ENOENT;
			goto err_put_syncobjs;
		}
		if (!drm_syncobj_point_valid(array[i].syncobj, items[i].value)) {
			ret = -EINVAL;
			i++;
			goto err_put_syncobjs;
		}
		array[i].value = items[i].value;
	}

	kfree(items);

	return array;

err_put_syncobjs:
	drm_syncobj_array_free(array, i);

err_free_handles:
	kfree(items);

	return ERR_PTR(ret);
}

/**
 * TODO
 */
struct drm_syncobj_array_item *
drm_syncobj_array_from_user(struct drm_file *file_private,
			    bool use_items,
			    void __user *user_data,
			    u32 count_items)
{
	if (use_items)
		return drm_syncobj_array_from_items(file_private,
						    user_data,
						    count_items);
	return drm_syncobj_array_from_handles(file_private,
					      user_data,
					      count_items);
}

int
drm_syncobj_wait_ioctl(struct drm_device *dev, void *data,
		       struct drm_file *file_private)
{
	struct drm_syncobj_wait *args = data;
	struct drm_syncobj_array_item *array;
	int ret = 0;

	if (!drm_core_check_feature(dev, DRIVER_SYNCOBJ))
		return -EOPNOTSUPP;

	if (args->flags & ~(DRM_SYNCOBJ_WAIT_FLAGS_WAIT_ALL |
			    DRM_SYNCOBJ_WAIT_FLAGS_WAIT_FOR_SUBMIT |
			    DRM_SYNCOBJ_WAIT_FLAGS_ITEMS))
		return -EINVAL;

	if (args->count_handles == 0)
		return -EINVAL;

	array = drm_syncobj_array_from_user(file_private,
					    args->flags & DRM_SYNCOBJ_WAIT_FLAGS_ITEMS,
					    u64_to_user_ptr(args->handles),
					    args->count_handles);
	if (IS_ERR(array))
		return PTR_ERR(array);

	ret = drm_syncobj_array_wait(dev, file_private, args, array);

	drm_syncobj_array_free(array, args->count_handles);

	return ret;
}

int
drm_syncobj_reset_ioctl(struct drm_device *dev, void *data,
			struct drm_file *file_private)
{
	struct drm_syncobj_array *args = data;
	struct drm_syncobj_array_item *array;
	uint32_t i;
	int ret = 0;

	if (!drm_core_check_feature(dev, DRIVER_SYNCOBJ))
		return -EOPNOTSUPP;

	if (args->flags & ~DRM_SYNCOBJ_ARRAY_FLAGS_ITEMS)
		return -EINVAL;

	if (args->count_handles == 0)
		return -EINVAL;

	array = drm_syncobj_array_from_user(file_private,
					    args->flags & DRM_SYNCOBJ_ARRAY_FLAGS_ITEMS,
					    u64_to_user_ptr(args->handles),
					    args->count_handles);
	if (IS_ERR(array))
		return PTR_ERR(array);

	for (i = 0; i < args->count_handles; i++) {
		ret = drm_syncobj_replace_fence(array[i].syncobj,
						array[i].value, NULL);
		if (ret)
			break;
	}

	drm_syncobj_array_free(array, args->count_handles);

	return ret;
}

int
drm_syncobj_signal_ioctl(struct drm_device *dev, void *data,
			 struct drm_file *file_private)
{
	struct drm_syncobj_array *args = data;
	struct drm_syncobj_array_item *array;
	uint32_t i;

	if (!drm_core_check_feature(dev, DRIVER_SYNCOBJ))
		return -EOPNOTSUPP;

	if (args->flags & ~DRM_SYNCOBJ_ARRAY_FLAGS_ITEMS)
		return -EINVAL;

	if (args->count_handles == 0)
		return -EINVAL;

	array = drm_syncobj_array_from_user(file_private,
					    args->flags & DRM_SYNCOBJ_ARRAY_FLAGS_ITEMS,
					    u64_to_user_ptr(args->handles),
					    args->count_handles);
	if (IS_ERR(array))
		return PTR_ERR(array);

	for (i = 0; i < args->count_handles; i++)
		drm_syncobj_signal(array[i].syncobj, array[i].value);

	drm_syncobj_array_free(array, args->count_handles);

	return 0;
}

int
drm_syncobj_read_timeline_ioctl(struct drm_device *dev, void *data,
				struct drm_file *file_private)
{
	struct drm_syncobj_array *args = data;
	struct drm_syncobj_item *items;
	int ret = 0;
	u32 i;

	if (!drm_core_check_feature(dev, DRIVER_SYNCOBJ_TIMELINE))
		return -EOPNOTSUPP;

	if (args->flags != DRM_SYNCOBJ_ARRAY_FLAGS_ITEMS)
		return -EINVAL;

	if (args->count_handles == 0)
		return -EINVAL;

	items = kmalloc_array(args->count_handles, sizeof(*items), GFP_KERNEL);
	if (items == NULL)
		return -ENOMEM;

	if (copy_from_user(items, u64_to_user_ptr(args->handles),
			   sizeof(*items) * args->count_handles)) {
		ret = -EFAULT;
		goto err_free_handles;
	}

	for (i = 0; i < args->count_handles; i++) {
		struct drm_syncobj *syncobj;

		if (items[i].pad != 0) {
			ret = -EINVAL;
			goto err_free_handles;
		}

		syncobj = drm_syncobj_find(file_private, items[i].handle);
		if (!syncobj) {
			ret = -ENOENT;
			goto err_free_handles;
		}

		spin_lock(&syncobj->lock);
		items[i].value = syncobj->timeline.value;
		spin_unlock(&syncobj->lock);
		drm_syncobj_put(syncobj);
	}

	if (copy_to_user(u64_to_user_ptr(args->handles), items,
			 sizeof(*items) * args->count_handles)) {
		ret = -EFAULT;
		goto err_free_handles;
	}

err_free_handles:
	kfree(items);

	return ret;
}
