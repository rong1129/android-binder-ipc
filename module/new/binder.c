/*
 * Android Binder IPC driver
 * Copyright (c) 2012 Rong Shen <rong1129@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/kref.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>

#include "msg_queue.h"
#include "binder.h"


#define MAX_TRANSACTION_SIZE			4000
#define TRANSACTION_HASH_BUCKET_SIZE		16

#define OBJ_ID_INIT(owner, binder)		{ (owner), (binder) }


typedef struct obj_id {
	void *owner;
	void *binder;
} obj_id_t;

typedef enum {
	BINDER_EVT_OBJ_DEAD = 1,
} obj_event_t;


struct binder_proc {
	spinlock_t lock;
	struct rb_root thread_tree;

	spinlock_t obj_lock;
	struct rb_root obj_tree;

	struct msg_queue *queue;

	int non_block;

	pid_t pid;
	int max_threads;
};

struct binder_thread {
	pid_t pid;

	struct rb_node rb_node;
	struct msg_queue *queue;

	int non_block;

	unsigned int num_pending;
	struct list_head pending_transactions[TRANSACTION_HASH_BUCKET_SIZE];
};

struct binder_notifier {
	struct list_head list;
	int event;
	void *cookie;
	struct msg_queue *notify_queue;
};

struct binder_obj {
	obj_id_t obj_id;
	void *real_cookie;

	struct rb_node rb_node;

	spin_lock_t lock;	// used for notifiers only
	struct list_head notifiers;	// TODO: slow deletion
};

#define bcmd_data_transaction	binder_transaction_data

struct bcmd_data_notifier {
	void *handle;
	void *cookie;
};

struct bcmd_msg_buf {
	void *data;
	size_t data_size;

	void *offsets;
	size_t offsets_size;
}

struct bcmd_msg {
	struct list_head __list;	// has to be the first field so we can cast it around

	obj_id_t obj_id;
	unsigned int type;
	unsigned int code;
	struct bcmd_msg_buf *buf;

	pid_t sender_pid;
	uid_t sender_euid;

	void *cookie;
	struct msg_queue *reply_queue;
};


static obj_t *context_mgr_obj;
static uid_t context_mgr_uid;		// compat


static inline void obj_id_init(obj_it_t *obj_id, struct binder_proc *proc, void *binder)
{
	obj_id->owner = proc->queue;
	obj_id->binder = binder;
}

static inline int obj_id_cmp(obj_id_t *a, obj_id_t *b)
{
	size_t sign;

	if ((sign = a->owner - b->owner))
		return (sign > 0) ? 1 : -1;

	if ((sign = a->binder - b->binder))
		return (sign > 0) ? 1 : -1;
	else
		return 0;
}

static struct binder_proc *binder_new_proc(struct file *filp)
{
	struct binder_proc *proc;

	proc = kmalloc(sizeof(*proc), GFP_KERNEL);
	if (!proc)
		return NULL;

	proc->non_block = (filp->f_flags & O_NONBLOCK) ? 1 : 0;
	proc->queue = create_msg_queue(0, proc->non_block, free_transaction);
	if (!proc->queue) {
		kfree(proc);
		return NULL;
	}

	proc->pid = task_tgid_vnr(current);
	proc->max_threads = 0;

	spin_lock_init(&proc->lock);
	proc->thread_tree.rb_node = NULL;

	spin_lock_init(&proc->obj_lock);
	proc->obj_tree.rb_node = NULL;

	return proc;
}

static int binder_free_proc(struct binder_proc *proc)
{
	struct rb_node *n;

	free_msg_queue(proc->queue);

	while (n = rb_first(&proc->obj_tree)) {
		obj = rb_entry(n, struct binder_obj, rb_node);
	
		rb_erase(n, &proc->obj_tree);
		if (obj->obj_id.owner != proc->queue) {	// references
			BUG_ON(!list_empty(&obj->notifiers));
			kfree(obj);
		} else {
			struct binder_notifier *notifier;
			struct bcmd_msg *msg = NULL;

			list_for_each_entry_safe(notifier, &obj->notifiers, list) {
				list_del(&notifier->list);

				if (!msg) {
					msg = kmalloc(sizeof(*msg), GFP_KERNEL); // TODO: nasty
					if (!msg)
						return -ENOMEM;
				}

				msg->type = BR_DEAD_BINDER;
				msg->obj_id = obj->obj_id;
				msg->cookie = notifier->cookie;
				if (!bcmd_write_msg(notifier->notify_queue, msg))
					msg = NULL;
			}
			if (msg)
				kfree(msg);
		}
	}
	
	// free threads

	kfree(proc);
	return 0;
}

static struct binder_thread *binder_new_thread(struct file *filp, pid_t pid)
{	
	struct binder_thread *thread;
	int i;

	thread = kmalloc(sizeof(*thread), GFP_KERNEL);
	if (!thread)
		return NULL;

	thread->non_block = (filp->f_flags & O_NONBLOCK) ? 1 : 0;
	thread->queue = create_msg_queue(0, thread->non_block, free_transaction);
	if (!thread->queue) {
		kfree(thread);
		return NULL;
	}

	thread->pid = pid;

	thread->num_pending = 0;
	for (i = 0; i < sizeof(thread->pending_transactions) / sizeof(thread->pending_transactions[0]); i++)
		INIT_LIST_HEAD(&thread->pending_transactions[i]);

	return thread;
}

static struct binder_thread *binder_get_thread(struct binder_proc *proc, struct file *filp)
{
	struct rb_node **p = &proc->thread_tree.rb_node;
	struct rb_node *parent = NULL;
	struct binder_thread *thread;
	pid_t pid = task_pid_vnr(current);

	spin_lock(&proc->lock);
	while (*p) {
		parent = *p;
		thread = rb_entry(parent, struct binder_thread, rb_node);

		if (pid < thread->pid)
			p = &(*p)->rb_left;
		else if (pid > thread->pid)
			p = &(*p)->rb_right;
		else {
			spin_unlock(&proc->lock);
			return thread;
		}
	}
	spin_unlock(&proc->lock);

	thread = binder_new_thread(filp, pid);
	if (!thread)
		return NULL;

	spin_lock(&proc->lock);
	rb_link_node(&thread->rb_node, parent, p);
	rb_insert_color(&thread->rb_node, &proc->thread_tree);
	spin_unlock(&proc->lock);

	return thread;
}

static struct binder_obj *_binder_find_obj(struct binder_proc *proc, void *owner, void *binder)
{
	struct rb_node **p = &proc->obj_tree.rb_node;
	struct rb_node *parent = NULL;
	struct binder_obj *obj;
	obj_id_t obj_id = OBJ_ID_INIT(owner, binder);
	int r;

	spin_lock(&proc->obj_lock);
	while (*p) {
		parent = *p;
		obj = rb_entry(parent, struct binder_obj, rb_node);

		r = obj_id_cmp(&obj_id, &obj->obj_id);
		if (r < 0)
			p = &(*p)->rb_left;
		else if (r > 0)
			p = &(*p)->rb_right;
		else {
			spin_unlock(&proc->obj_lock);
			return obj;
		}
	}
	spin_unlock(&proc->obj_lock);

	return NULL;
}

static struct binder_obj *binder_find_obj(struct binder_proc *proc, void *binder)
{
	return _binder_find_obj(proc, proc->queue, binder);
}

static struct binder_obj *_binder_new_obj(struct binder_proc *proc, void *owner, void *binder)
{
	struct rb_node **p = &proc->obj_tree.rb_node;
	struct rb_node *parent = NULL;
	struct binder_obj *obj, *new_obj;
	obj_it_t obj_id = OBJ_ID_INIT(owner, binder);
	int r;

	new_obj = kmalloc(sizeof(*obj), GFP_KERNEL);
	if (!new_obj)
		return NULL;
	new_obj->obj_id = obj_id;
	spin_lock_init(&new_obj->lock);
	INIT_LIST_HEAD(&new_obj->notifiers);

	spin_lock(&proc->obj_lock);
	while (*p) {
		parent = *p;
		obj = rb_entry(parent, struct binder_obj, rb_node);

		r = obj_id_cmp(&obj_id, &obj->obj_id);
		if (r < 0)
			p = &(*p)->rb_left;
		else if (r > 0)
			p = &(*p)->rb_right;
		else {	// other thread has created an object before we do
			spin_unlock(&proc->obj_lock);
			kfree(new_obj);
			return obj;
		}
	}

	rb_link_node(&new_obj->rb_node, parent, p);
	rb_insert_color(&new_obj->rb_node, &proc->obj_tree);

	spin_unlock(&proc->obj_lock);

	return new_obj;
}

static struct binder_obj *binder_new_obj(struct binder_proc *proc, void *binder)
{
	return _binder_new_obj(proc, proc->queue, binder);
}

static struct bcmd_msg *binder_alloc_msg(size_t data_size, size_t offsets_size)
{
	struct bcmd_msg *msg;
	struct bcmd_msg_buf *buf;
	void *p;

	msg_size = ALIGN(sizeof(*msg), sizeof(void *));
	buf_size = ALIGN(data_size, sizeof(void *)) + ALIGN(offsets_size, sizeof(void *));

	msg = kmalloc(msg_size + buf_size, GFP_KERNEL);
	if (!p)
		return NULL;

	buf = (struct bcmd_msg_buf *)((void *)msg + msg_size);
	buf->data_size = data_size;
	buf->offsets_size = offsets_size;

	msg->buf = buf;
	return msg;
}

static int bcmd_write_flat_obj(struct binder_proc *proc, struct binder_thread *thread, struct flat_binder_object *bp)
{
	unsigned long type = bp->type;

	switch (type) {
		case BINDER_TYPE_BINDER:
		case BINDER_TYPE_WEAK_BINDER: {
			struct binder_obj *obj;

			obj = binder_find_obj(proc, bp->binder);
			if (!obj) {
				obj = binder_new_obj(proc, bp->binder);
				/* cookie isn't worth being passed around, so we record it in the object. */
				obj->real_cookie = bp->cookie;
				if (!obj)
					return -ENOMEM;
			}

			bp->type = (type == BINDER_TYPE_BINDER) ? BINDER_TYPE_HANDLE : BINDER_TYPE_WEAK_HANDLE;
			/* Since we are not passing cookie, we can hijack bp->cookie to pass
			   the binder owner to the reader */
			bp->cookie = obj->obj_id.owner;
			break;
		}

		case BINDER_TYPE_HANDLE:
		case BINDER_TYPE_WEAK_HANDLE: {
			struct binder_obj *obj;

			obj = _binder_find_obj(proc, bp->cookie, bp->binder);
			if (!obj)
				return -EINVAL;
			break;
		}

		default: 
			return -EINVAL;
	}

	return 0;
}

static int bcmd_read_flat_obj(struct binder_proc *proc, struct binder_thread *thread, struct flat_binder_object *bp)
{
	unsigned long type = bp->type;

	switch (type) {
		case BINDER_TYPE_HANDLE:
		case BINDER_TYPE_WEAK_HANDLE: {
			struct binder_obj *obj;

			obj = _binder_find_obj(proc, bp->cookie, bp->binder);
			if (obj) {
				if (bp->cookie == proc->queue) {
					bp->type = (type == BINDER_TYPE_HANDLE) ? BINDER_TYPE_BINDER : BINDER_TYPE_WEAK_BINDER;
					/* we reached the object owner, so it's time to restore the real cookie back */
					bp->cookie = obj->real_cookie;
				}
			} else {
				obj = _binder_new_obj(proc, bp->cookie, bp->binder);
				if (!obj)
					return -ENOMEM;
			}
			break;
		}

		/* No more these types */
		case BINDER_TYPE_BINDER:
		case BINDER_TYPE_WEAK_BINDER:

		default: 
			return -EFAULT;
	}

	return 0;
}

static int bcmd_init_msg_buf(struct binder_proc *proc, struct binder_thread *thread, struct bcmd_msg_buf *buf, struct bcmd_data_transaction *tdata)
{
	size_t *p = buf->offsets, *ep = buf->offsets + buf->offsets_size;
	struct flat_binder_object *bp;
	int r;

	if (copy_from_user(buf->data, tdata->buffer, buf->data_size) ||
	    copy_from_user(buf->offsets, tdata->offsets, buf->offsets_size))
		return -EFAULT;

	while (p < ep) {
		off = *p;
		if (off + sizeof(*bp) > buf->data_size)
			return -EFAULT;

		bp = (struct flat_binder_object *)(buf->data + off);

		r = bcmd_write_flat_obj(proc, thread, bp);
		if (r < 0)
			return r;
	}

	return 0;
}

static inline int bcmd_write_msg(struct msg_queue *q, struct bcmd_msg *msg)
{
	int r;

	if (get_msg_queue(q) < 0)
		return -EFAULT;

	r = write_msg_queue(q, (struct list_head *)msg);

	put_msg_queue(q);
	return r;
}

static int bcmd_write_transaction(struct binder_proc *proc, struct binder_thread *thread, struct bcmd_data_transaction *tdata)
{
	struct binder_obj *obj;
	struct bcmd_msg *msg;
	uint32_t err;
	void *binder = (void *)tdata->target.handle;

	if (unlikely(!binder))
		obj = context_mgr_obj;
	else
		obj = binder_find_obj(proc, binder);
	if (!obj) {
		err = BR_FAILED_REPLY;
		goto failed_obj;
	}

	msg = binder_alloc_msg(tdata->data_size, tdata->offsets_size);
	if (!msg) {
		err = BR_FAILED_REPLY;
		goto failed_msg;
	}

	msg->type = BC_TRANSACTION;
	msg->obj_id = obj->obj_id;
	msg->code = tdata->code;
	msg->flags = tdata->flags;
	msg->sender_pid = proc->pid;
	msg->sender_euid = current->cred->euid;
	msg->reply_queue = (tdata->flags & TF_ONE_WAY) ? NULL : thread->queue; 

	if (tdata->data_size > 0) {
		if (!bcmd_init_msg_buf(proc, thread, msg->buf, tdata)) {
			err = BR_FAILED_REPLY;
			goto failed_load;
		}
	}

	if (bcmd_write_msg(obj->obj_id.owner, msg) < 0) {
		err = BR_DEAD_REPLY;
		goto failed_write;
	}

	if (tdata->flags & TF_ONE_WAY) {
		// push transaction id onto pending stack
	}

	return 0;

failed_write:
failed_load:
	kfree(msg);
failed_msg:
failed_obj:
	thread->last_error = err;
	return -1;
}

static int bcmd_write_notifier(struct binder_proc *proc, struct bcmd_data_notifier *notifier, int msg_type)
{
	struct binder_obj *obj;
	struct bcmd_msg *msg;
	uint32_t err;
	void *binder = (void *)notifier->handle;

	obj = binder_find_obj(proc, binder);
	if (!obj) {
		err = BR_FAILED_REPLY;
		goto failed_obj;
	}

	msg = binder_alloc_msg(0, 0);
	if (!msg) {
		err = BR_FAILED_REPLY;
		goto failed_msg;
	}

	msg->type = msg_type;
	msg->obj_id = obj->obj_id;
	msg->cookie = notifier->cookie;
	msg->reply_queue = proc->queue;		// queue to send notification to

	if (bcmd_write_msg(obj->obj_id.owner, msg) < 0) {
		err = BR_DEAD_REPLY;
		goto failed_write;
	}

	return 0;

failed_write:
	kfree(msg);
failed_msg:
failed_obj:
	thread->last_error = err;
	return -1;
}

static long binder_thread_write(struct binder_proc *proc, struct binder_thread *thread, void __user *buf, unsigned long size)
{
	uint32_t bcmd;
	void __user *p = buf, *ep = buf + size;
	unsigned long pos = 0;
	int err = 0;

	while ((p + sizeof(bcmd)) < ep) {
		if (get_user(bcmd, p))
			return -EFAULT;
		p += sizeof(bcmd);

		switch (bcmd) {
			case BC_TRANSACTION:
			case BC_REPLY:  {
				struct bcmd_data_transaction tdata;

				if ((p + sizeof(tdata)) > ep || copy_from_user(&tdata, p, sizeof(tdata)))
					return -EFAULT;
				p += sizeof(tdata);

				if (tdata->data_size > 0) {
					size_t objs_size = tdata->offsets_size / sizeof(size_t) * sizeof(struct flat_binder_object);

					if (objs_size + tdata->offsets_size > tdata->data_size || tdata->data_size > MAX_TRANSACTION_SIZE)
						return -EINVAL;
				}

				if (bcmd == BC_TRANSACTION)
					err += bcmd_write_transaction(proc, thread, &tdata);
				else
					err += bcmd_write_reply(proc, thread, &tdata);
				break;
			}

			case BC_REQUEST_DEATH_NOTIFICATION:
			case BC_CLEAR_DEATH_NOTIFICATION: {
				struct bcmd_data_notifier notifier;

				if ((p + sizeof(notifier)) > ep || copy_from_user(&notifier, p, sizeof(notifier)))
					return -EFAULT;
				p += sizeof(notifier);

				err += bcmd_write_notifier(proc, &notifier, bcmd);
				break;
			}

			default:
				return -EINVAL;
		}
	}

	if (err) {	// flag the event, so next binder_thread_read would pick it up
	}

	return p - buf;
}

static long bcmd_read_transaction(struct binder_proc *proc, struct binder_thread *thread, struct bcmd_msg *msg, void __user *buf, unsigned long size)
{
	struct bcmd_data_transaction tdata;
	struct bcmd_msg_buf *mbuf;
	unsigned long off;
	void __user *data_buf;
	size_t *p, *ep;
	struct flat_binder_object *bp;

	off = ALIGN(sizeof(tdata), sizeof(void *));
	if (off + mbuf->data_size > size)
		return 0;
	data_buf = buf + off;
	
	tdata.target.ptr = msg->obj_id.binder;
	tdata.code = msg->code;
	tdata.flags = msg->flags;
	tdata.sender_pid = msg->sender_pid;
	tdata.sender_euid = msg->sender_euid;
	
	tdata.data_size = mbuf->data_size;
	tdata.offsets_size = mbuf->offsets_size;
	
	tdata.ptr.buffer = data_buf;
	tdata.ptr.offsets = data_buf + (mbuf->offsets - mbuf->data);

	p = mbuf->offsets;
	ep = mbuf->offsets + mbuf->offsets_size;
	while (p < ep) {
		bp = (struct flat_binder_object *)(buf->data + *p);

		r = bcmd_read_flat_obj(proc, thread, bp);
		if (r < 0)
			return r;
	}

	if (copy_to_user(buf, &tdata, sizeof(tdata)) ||
	    copy_to_user(data_buf, mbuf->data, mbuf->data_size))
		return -EFAULT;
	
	return (off + mbuf->data_size);
}

static long bcmd_read_notifier(struct binder_proc *proc, struct binder_thread *thread, struct bcmd_msg *msg)
{
	struct binder_notifier *notifier;
	struct binder_obj *obj;

	obj = _binder_find_obj(proc, proc->queue, msg->obj_id.binder);
	if (!obj)
		return -EINVAL;

	if (msg->type == BC_REQUEST_DEATH_NOTIFICATION) {
		// TODO: check previous subscrition?
		notifier = kmalloc(sizeof(*notifier), msg);
		if (!notifier)
			return -ENOMEM;
		notifier->event = BINDER_EVT_OBJ_DEAD;	// TODO: the only event (hard-coded)
		notifier->cookie = msg->cookie;
		notifier->notify_queue = msg->reply_queue;

		spin_lock(&obj->lock);
		list_add_tail(&notifier->list, &obj->notifiers);
		spin_unlock(&obj->lock);
	} else {
		int found = 0;

		spin_lock(&obj->lock);
		list_for_each_entry_safe(notifier, &obj->notifiers, list) {
			if (notifier->event == BINDER_EVT_OBJ_DEAD &&
			    notifier->cookie == msg->cookie &&
			    notifier->notify_queue == msg->reply_queue) {
				found = 1;
				list_del(&notifier->list);
				break;
			}
		}
		spin_unlock(&obj->lock);

		if (found)
			kfree(notifier);
	}

	return 0;
}

static long binder_thread_read(struct binder_proc *proc, struct binder_thread *thread, void __user *buf, unsigned long size)
{
	struct bcmd_msg *msg;
	struct msg_queue *q;
	long n;
	int r;

	while (1) {
		if (!msg_queue_empty(thread->queue))
			q = thread->queue;
		else if (!msg_queue_empty(proc->queue))
			q = proc->queue;
		else {	// sleep
		}

		r = read_msg_queue(q, (struct list_head **)&msg);
		if (r < 0)
			return -EIO;

		switch (msg->type) {
			case BC_TRANSACTION:
			case BC_REPLY:
				n = bcmd_read_transaction(proc, thread, msg, buf, size);
				if (n > 0) {
					buf += n;
					size -= n;
				}
				break;

			case BC_REQUEST_DEATH_NOTIFICATION:
			case BC_CLEAR_DEATH_NOTIFICATION:
				n = bcmd_read_notifier(proc, thread, msg);
				break;

			case BR_DEAD_BINDER:
		}

	}
}

static inline int cmd_write_read(struct binder_proc *proc, struct binder_thread *thread, struct binder_write_read *bwr)
{
	if (bwr->write_size > 0) {
		r = binder_thread_write(proc, thread, bwr->write_buffer + bwr->write_consumed, bwr->write_size);
		if (r < 0)
			return r;
		bwr->write_consumed += r;
	}

	if (bwr->read_size > 0) {
		r = binder_thread_read(proc, thread, bwr->read_buffer + bwr->read_consumed, bwr->read_size);
		if (r < 0)
			return r;
		bwr->read_consumed += r;
	}

	return 0;
}

static inline int cmd_thread_exit(struct binder_proc *proc, struct binder_thread *thread)
{
}

static inline int cmd_set_max_threads(struct binder_proc *proc, int max_threads)
{
	spin_lock(&proc->lock);
	proc->max_threads = max_threads;
	spin_unlock(&proc->lock);
	return 0;
}

static inline int cmd_set_context_mgr(struct binder_proc *proc)
{
	if (!context_mgr_obj) 
		return -EBUSY;

	// TODO: protection
	context_mgr_obj = binder_new_obj(proc, NULL);
	if (!context_mgr_obj)
		return -ENOMEM;

	context_mgr_uid = current->cred->euid;
	return 0;
}

static int binder_open(struct inode *nodp, struct file *filp)
{
	struct binder_proc *proc;

	if (filp->private_data)		// already in use
		return -EBUSY;

	proc = binder_new_proc(filp);
	if (!proc)
		return -ENOMEM;

	filp->private_data = proc;
	return 0;
}

static int binder_release(struct inode *nodp, struct file *filp)
{
	struct binder_proc *proc = filp->private_data;

	binder_free_proc(proc);
}

static long binder_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct binder_proc *proc = filp->private_data;
	struct binder_thread *thread;
	unsigned int size = _IOC_SIZE(cmd);
	void __user *ubuf = (void __user *)arg;

	thread = binder_get_thread(proc, filp);
	if (!thread)
		return -ENOMEM;

	switch (cmd) {
		case BINDER_WRITE_READ: {
			struct binder_write_read bwr;
			int r;

			if (size != sizeof(bwr))
				return -EINVAL;
			if (copy_from_user(&bwr, ubuf, sizeof(bwr)))
				return -EFAULT;

			r = cmd_write_read(proc, thread, &bwr);
			if (r < 0)
				return r;

			if (copy_to_user(ubuf, &bwr, sizeof(bwr)))
				return -EFAULT;
		}

		case BINDER_THREAD_EXIT:
			return cmd_thread_exit(proc, thread);

		case BINDER_SET_MAX_THREADS: {
			int max_threads;

			if (size != sizeof(int))
				return -EINVAL;
			if (get_user(max_threads, ubuf))
				return -EFAULT;

			return cmd_set_max_threads(proc, max_threads);
		}

		case BINDER_VERSION:
			if (size != sizeof(struct binder_version))
				ret = -EINVAL;
			if (put_user(BINDER_CURRENT_PROTOCOL_VERSION, &((struct binder_version *)ubuf)->protocol_version))
				return -EFAULT;
			return 0;

		case BINDER_SET_CONTEXT_MGR:
			return cmd_set_context_mgr(proc);

		default:
			return -EINVAL;
	}
}

static unsigned int binder_poll(struct file *filp, struct poll_table_struct *wait)
{
}

static int binder_flush(struct file *filp, fl_owner_t id)
{
	return 0;	// compat
}

static int binder_mmap(struct file *filp, struct vm_area_struct *vma)
{
	return 0;	// compat
}

static const struct file_operations binder_fops = {
	.owner = THIS_MODULE,
	.open = binder_open,
	.release = binder_release,
	.unlocked_ioctl = binder_ioctl,
	.poll = binder_poll,
	.mmap = binder_mmap,
	.flush = binder_flush
};

static struct miscdevice binder_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "binder",
	.fops = &binder_fops
};

static int __init binder_init(void)
{
}

static void __exit binder_exit(void)
{
}

module_init(binder_init);
//module_exit(binder_exit);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Rong Shen");
