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
#include <linux/module.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/poll.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>

#include "msg_queue.h"
#include "binder.h"


#define MAX_TRANSACTION_SIZE			4000
#define OBJ_ID_INIT(owner, binder)		{ (owner), (binder) }
#define MSG_BUF_ALIGN(n)			ALIGN((n), sizeof(void *))


enum {	// compat: review looper idea
	BINDER_LOOPER_STATE_INVALID     = 0x00,
	BINDER_LOOPER_STATE_REGISTERED  = 0x01,
	BINDER_LOOPER_STATE_ENTERED     = 0x02,
	BINDER_LOOPER_STATE_READY       = 0x03		// compat
};


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

	pid_t pid;

	int max_threads;
	atomic_t num_loopers, busy_loopers, requested_loopers;
};

struct binder_thread {
	pid_t pid;

	struct rb_node rb_node;
	struct msg_queue *queue;

	int state;
	int non_block;
	unsigned int last_error;

	unsigned int pending_replies;
	struct list_head incoming_transactions;
};

struct binder_notifier {
	struct list_head list;
	int event;
	void *cookie;
	struct msg_queue *notify_queue;
};

struct binder_obj {
	obj_id_t obj_id;
	void *real_cookie;		// named differently to be less confusing

	struct rb_node rb_node;

	spinlock_t lock;		// used for notifiers only
	struct list_head notifiers;	// TODO: slow deletion
};

#define bcmd_transaction_data	binder_transaction_data

struct bcmd_notifier_data {
	void *binder;
	void *cookie;
};

struct bcmd_msg_buf {
	void *data;
	void *offsets;

	size_t data_size;
	size_t offsets_size;
	size_t buf_size;
};

struct bcmd_msg {
	struct list_head list;

	obj_id_t obj_id;
	unsigned int type;		// compat: review all data types in/out of the ioctl
	unsigned int code;
	unsigned int flags;
	void *cookie;

	struct bcmd_msg_buf *buf;

	pid_t sender_pid;
	uid_t sender_euid;

	struct msg_queue *reply_queue;
};


static struct binder_obj *context_mgr_obj;	// compat: is context mgr necessary?
static uid_t context_mgr_uid = -1;


static inline void obj_id_init(obj_id_t *obj_id, struct binder_proc *proc, void *binder)
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

	return 0;
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
	obj_id_t obj_id = OBJ_ID_INIT(owner, binder);
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

// used by the queue owner
inline int _bcmd_read_msg(struct msg_queue *q, struct bcmd_msg **pmsg)
{
	struct list_head *list = &(*pmsg)->list;
	int r;

	r = read_msg_queue(q, &list);
	if (!r)
		*pmsg = container_of(list, struct bcmd_msg, list);
	return r;
}

// used by any process
inline int bcmd_read_msg(struct msg_queue *q, struct bcmd_msg **pmsg)
{
	int r;

	if (get_msg_queue(q) < 0)
		return -EFAULT;

	r = _bcmd_read_msg(q, pmsg);

	put_msg_queue(q);
	return r;
}

// used by the queue owner
inline int _bcmd_write_msg(struct msg_queue *q, struct bcmd_msg *msg)
{
	return write_msg_queue(q, &msg->list);
}

// used by any process
inline int bcmd_write_msg(struct msg_queue *q, struct bcmd_msg *msg)
{
	int r;

	if (get_msg_queue(q) < 0)
		return -EFAULT;

	r = _bcmd_write_msg(q, msg);

	put_msg_queue(q);
	return r;
}

// used by the queue owner
inline int _bcmd_write_msg_head(struct msg_queue *q, struct bcmd_msg *msg)
{
	return write_msg_queue_head(q, &msg->list);
}

// used by any process
inline int bcmd_write_msg_head(struct msg_queue *q, struct bcmd_msg *msg)
{
	int r;

	if (get_msg_queue(q) < 0)
		return -EFAULT;

	r = _bcmd_write_msg_head(q, msg);

	put_msg_queue(q);
	return r;
}

static struct bcmd_msg *binder_alloc_msg(size_t data_size, size_t offsets_size)
{
	size_t msg_size, buf_size;
	struct bcmd_msg *msg;
	struct bcmd_msg_buf *buf;

	msg_size = MSG_BUF_ALIGN(sizeof(*msg)) + MSG_BUF_ALIGN(sizeof(*buf));
	buf_size = MSG_BUF_ALIGN(data_size) + MSG_BUF_ALIGN(offsets_size);

	msg = kmalloc(msg_size + buf_size, GFP_KERNEL);
	if (!msg)
		return NULL;

	buf = (struct bcmd_msg_buf *)((void *)msg + MSG_BUF_ALIGN(sizeof(*msg)));
	buf->data = (void *)msg + msg_size;
	buf->offsets = (void *)msg + msg_size + MSG_BUF_ALIGN(data_size);

	buf->data_size = data_size;
	buf->offsets_size = offsets_size;
	buf->buf_size = buf_size;

	msg->buf = buf;
	return msg;
}

static struct bcmd_msg *binder_realloc_msg(struct bcmd_msg *msg, size_t data_size, size_t offsets_size)
{
	size_t buf_size;
	struct bcmd_msg_buf *buf = msg->buf;

	buf_size = MSG_BUF_ALIGN(data_size) + MSG_BUF_ALIGN(offsets_size);
	if (buf->buf_size >= buf_size) {
		buf->offsets = (void *)buf->data + MSG_BUF_ALIGN(data_size);

		buf->data_size = data_size;
		buf->offsets_size = offsets_size;
		return msg;
	}

	kfree(msg);
	return binder_alloc_msg(data_size, offsets_size);
}

static void free_queued_msg(struct list_head *entry)
{
	struct bcmd_msg *msg = container_of(entry, struct bcmd_msg, list);

	if (msg->type == BC_TRANSACTION) {
		BUG_ON(!msg->reply_queue);

		msg->type = BR_DEAD_BINDER;
		if (!bcmd_write_msg(msg->reply_queue, msg))
			return;
	}

	kfree(msg);
}

static struct binder_proc *binder_new_proc(struct file *filp)
{
	struct binder_proc *proc;

	proc = kmalloc(sizeof(*proc), GFP_KERNEL);
	if (!proc)
		return NULL;

	proc->queue = create_msg_queue(0, free_queued_msg);
	if (!proc->queue) {
		kfree(proc);
		return NULL;
	}

	proc->pid = task_tgid_vnr(current);
	proc->max_threads = 0;

	atomic_set(&proc->num_loopers, 0);
	atomic_set(&proc->requested_loopers, 0);
	atomic_set(&proc->busy_loopers, 0);

	spin_lock_init(&proc->lock);
	proc->thread_tree.rb_node = NULL;

	spin_lock_init(&proc->obj_lock);
	proc->obj_tree.rb_node = NULL;

	return proc;
}

static struct binder_thread *binder_new_thread(struct binder_proc *proc, struct file *filp, pid_t pid)
{	
	struct binder_thread *thread;

	thread = kmalloc(sizeof(*thread), GFP_KERNEL);
	if (!thread)
		return NULL;

	thread->queue = create_msg_queue(0, free_queued_msg);
	if (!thread->queue || get_msg_queue(proc->queue) < 0) {
		kfree(thread);
		return NULL;
	}

	thread->pid = pid;
	thread->state = 0;
	thread->last_error = 0;
	thread->non_block = (filp->f_flags & O_NONBLOCK) ? 1 : 0;	// compat

	thread->pending_replies = 0;
	INIT_LIST_HEAD(&thread->incoming_transactions);

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

	thread = binder_new_thread(proc, filp, pid);
	if (!thread)
		return NULL;

	spin_lock(&proc->lock);
	rb_link_node(&thread->rb_node, parent, p);
	rb_insert_color(&thread->rb_node, &proc->thread_tree);
	spin_unlock(&proc->lock);

	return thread;
}

static int binder_free_thread(struct binder_proc *proc, struct binder_thread *thread)
{
	struct bcmd_msg *msg, *next;

	put_msg_queue(proc->queue);
	free_msg_queue(thread->queue);

	list_for_each_entry_safe(msg, next, &thread->incoming_transactions, list) {
		list_del(&msg->list);

		msg->type = BR_DEAD_BINDER;

		BUG_ON(!msg->reply_queue);
		if (bcmd_write_msg(msg->reply_queue, msg) < 0)
			kfree(msg);
	}

	spin_lock(&proc->lock);
	rb_erase(&thread->rb_node, &proc->thread_tree);
	spin_unlock(&proc->lock);

	kfree(thread);
	return 0;
}

static int binder_free_obj(struct binder_proc *proc, struct binder_obj *obj)
{
	if (obj->obj_id.owner == proc->queue) {
		struct binder_notifier *notifier, *next;
		struct bcmd_msg *msg = NULL;

		list_for_each_entry_safe(notifier, next, &obj->notifiers, list) {
			list_del(&notifier->list);

			if (!msg) {
				msg = kmalloc(sizeof(*msg), GFP_KERNEL); // TODO: ugly
				if (!msg) {
					kfree(obj);
					return -ENOMEM;
				}
			}

			msg->type = BR_DEAD_BINDER;
			msg->obj_id = obj->obj_id;
			msg->cookie = notifier->cookie;
			if (!bcmd_write_msg(notifier->notify_queue, msg))
				msg = NULL;
		}
		if (msg)
			kfree(msg);
	} else {	// just reference
		BUG_ON(!list_empty(&obj->notifiers));
	}

	kfree(obj);
	return 0;
}

static int binder_free_proc(struct binder_proc *proc)
{
	struct rb_node *n;
	struct binder_thread *thread;
	struct binder_obj *obj;
	int r;

	free_msg_queue(proc->queue);

	while ((n = rb_first(&proc->thread_tree))) {
		thread = rb_entry(n, struct binder_thread, rb_node);
		r = binder_free_thread(proc, thread);
		if (r < 0)
			return r;
	}

	spin_lock(&proc->lock);
	while ((n = rb_first(&proc->obj_tree))) {
		obj = rb_entry(n, struct binder_obj, rb_node);

		rb_erase(n, &proc->obj_tree);

		r = binder_free_obj(proc, obj);
		if (r < 0)
			return r;
	}
	spin_unlock(&proc->lock);

	kfree(proc);
	return 0;
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

static int bcmd_write_msg_buf(struct binder_proc *proc, struct binder_thread *thread, struct bcmd_msg_buf *buf, struct bcmd_transaction_data *tdata)
{
	size_t *p = buf->offsets, *ep = buf->offsets + buf->offsets_size, off;
	struct flat_binder_object *bp;
	int r;

	if (copy_from_user(buf->data, tdata->data.ptr.buffer, buf->data_size) ||
	    copy_from_user(buf->offsets, tdata->data.ptr.offsets, buf->offsets_size))
		return -EFAULT;

	while (p < ep) {
		off = *p++;
		if (off + sizeof(*bp) > buf->data_size)
			return -EFAULT;

		bp = (struct flat_binder_object *)(buf->data + off);

		r = bcmd_write_flat_obj(proc, thread, bp);
		if (r < 0)
			return r;
	}

	return 0;
}

static int bcmd_write_transaction(struct binder_proc *proc, struct binder_thread *thread, struct bcmd_transaction_data *tdata, uint32_t bcmd)
{
	struct bcmd_msg *msg;
	struct msg_queue *q;
	obj_id_t obj_id;
	uint32_t err;

	if (bcmd == BC_TRANSACTION) {
		void *binder = (void *)tdata->target.handle;
		struct binder_obj *obj;

		if (unlikely(!binder))
			obj = context_mgr_obj;
		else
			obj = binder_find_obj(proc, binder);
		if (!obj) {
			err = BR_FAILED_REPLY;
			goto failed_obj;
		}

		q = obj->obj_id.owner;

		msg = binder_alloc_msg(tdata->data_size, tdata->offsets_size);
		if (!msg) {
			err = BR_FAILED_REPLY;
			goto failed_msg;
		}

		obj_id = obj->obj_id;
	} else {
		// compat: pop out the top transaction without checking
		if (list_empty(&thread->incoming_transactions)) {
			err = BR_FAILED_REPLY;
			goto failed_transaction;
		}
		msg = list_first_entry(&thread->incoming_transactions, struct bcmd_msg, list);
		list_del(&msg->list);

		q = msg->reply_queue;
		msg = binder_realloc_msg(msg, tdata->data_size, tdata->offsets_size);
		if (!msg) {
			err = BR_FAILED_REPLY;
			goto failed_msg;
		}

		obj_id_init(&obj_id, NULL, NULL);	// compat
	}

	msg->type = bcmd;
	msg->obj_id = obj_id;
	msg->code = tdata->code;
	msg->flags = tdata->flags;
	msg->sender_pid = proc->pid;
	msg->sender_euid = current->cred->euid;
	msg->reply_queue = ((bcmd == BC_REPLY) || (tdata->flags & TF_ONE_WAY)) ? NULL : thread->queue; 

	if (tdata->data_size > 0) {
		if (bcmd_write_msg_buf(proc, thread, msg->buf, tdata) < 0) {
			err = BR_FAILED_REPLY;
			goto failed_load;
		}
	}

	if (bcmd_write_msg(q, msg) < 0) {
		err = BR_DEAD_REPLY;
		goto failed_write;
	}

	if (bcmd == BC_TRANSACTION && !(tdata->flags & TF_ONE_WAY))
		thread->pending_replies++;

	// compat: Write TR-COMPLETE message back to the caller as per the protocol
	msg = binder_alloc_msg(0, 0);
	if (!msg) {
		err = BR_FAILED_REPLY;
		goto failed_complete;
	}
	msg->type = BR_TRANSACTION_COMPLETE;
	msg->obj_id = obj_id;
	msg->code = tdata->code;
	msg->flags = tdata->flags;
	if (_bcmd_write_msg(thread->queue, msg) < 0) {
		kfree(msg);
		err = BR_FAILED_REPLY;
		goto failed_complete;
	}

	return 0;

failed_write:
failed_load:
	kfree(msg);
failed_msg:
failed_transaction:
failed_obj:
failed_complete:
	thread->last_error = err;
	return -1;
}

static int bcmd_write_notifier(struct binder_proc *proc, struct binder_thread *thread, struct bcmd_notifier_data *notifier, uint32_t bcmd)
{
	struct binder_obj *obj;
	struct bcmd_msg *msg;
	uint32_t err;

	obj = binder_find_obj(proc, notifier->binder);
	if (!obj) {
		err = BR_FAILED_REPLY;
		goto failed_obj;
	}

	msg = binder_alloc_msg(0, 0);
	if (!msg) {
		err = BR_FAILED_REPLY;
		goto failed_msg;
	}

	msg->type = bcmd;
	msg->obj_id = obj->obj_id;
	msg->cookie = notifier->cookie;
	msg->reply_queue = proc->queue;		// notification sent to the process queue

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

static int bcmd_write_looper(struct binder_proc *proc, struct binder_thread *thread, uint32_t bcmd)
{
	uint32_t err = 0;

	switch (bcmd) {
		case BC_ENTER_LOOPER:
			if (thread->state & BINDER_LOOPER_STATE_READY)
				err = BR_FAILED_REPLY;
			else {
				thread->state |= BINDER_LOOPER_STATE_ENTERED;
				atomic_inc(&proc->num_loopers);
			}
			break;

		case BC_EXIT_LOOPER:
			if (thread->state & BINDER_LOOPER_STATE_ENTERED) {
				thread->state &= ~BINDER_LOOPER_STATE_READY;
				atomic_dec(&proc->num_loopers);
			} else
				err = BR_FAILED_REPLY;
			break;

		case BC_REGISTER_LOOPER:
			if (thread->state & BINDER_LOOPER_STATE_READY)
				err = BR_FAILED_REPLY;
			else
				atomic_dec(&proc->requested_loopers);
			break;

		default:
			err = BR_FAILED_REPLY;
			break;
	}

	if (err) {
		thread->last_error = err;
		return -1;
	}
	return 0;
}

static long binder_thread_write(struct binder_proc *proc, struct binder_thread *thread, void __user *buf, unsigned long size)
{
	void __user *p = buf, *ep = buf + size;
	uint32_t bcmd;
	int err = 0;

	while ((p + sizeof(bcmd)) <= ep) {
		if (get_user(bcmd, (uint32_t *)p))
			return -EFAULT;
		p += sizeof(bcmd);

		switch (bcmd) {
			case BC_TRANSACTION:
			case BC_REPLY:  {
				struct bcmd_transaction_data tdata;

				if ((p + sizeof(tdata)) > ep || copy_from_user(&tdata, p, sizeof(tdata)))
					return -EFAULT;
				p += sizeof(tdata);

				if (tdata.data_size > 0) {
					size_t objs_size = tdata.offsets_size / sizeof(size_t) * sizeof(struct flat_binder_object);

					if (objs_size + tdata.offsets_size > tdata.data_size || tdata.data_size > MAX_TRANSACTION_SIZE)
						return -EINVAL;
				}

				err += bcmd_write_transaction(proc, thread, &tdata, bcmd);
				break;
			}

			case BC_REQUEST_DEATH_NOTIFICATION:
			case BC_CLEAR_DEATH_NOTIFICATION: {
				struct bcmd_notifier_data notifier;

				if ((p + sizeof(notifier)) > ep || copy_from_user(&notifier, p, sizeof(notifier)))
					return -EFAULT;
				p += sizeof(notifier);

				err += bcmd_write_notifier(proc, thread, &notifier, bcmd);
				break;
			}

			case BC_ENTER_LOOPER:
			case BC_EXIT_LOOPER:
			case BC_REGISTER_LOOPER:
				err += bcmd_write_looper(proc, thread, bcmd);
				break;

			case BC_DEAD_BINDER_DONE:
				// TODO: do something?
				p += sizeof(void *);
				break;

			default:
				return -EINVAL;
		}
	}

	if (err)	// not compat: original binder would stop
		thread->last_error = BR_ERROR;

	return p - buf;
}

static long bcmd_read_transaction(struct binder_proc *proc, struct binder_thread *thread, struct bcmd_msg **pmsg, void __user *buf, unsigned long size)
{
	struct bcmd_transaction_data tdata;
	struct bcmd_msg *msg = *pmsg;
	struct bcmd_msg_buf *mbuf = msg->buf;
	uint32_t cmd = (msg->type == BC_TRANSACTION) ? BR_TRANSACTION : BR_REPLY;
	void __user *data_buf;
	size_t data_off, data_size, *p, *ep;
	struct flat_binder_object *bp;
	int r;

	data_off = MSG_BUF_ALIGN(sizeof(cmd) + sizeof(tdata));
	data_size = mbuf->data_size;
	if (data_off + data_size > size)
		return -ENOSPC;
	data_buf = buf + data_off;

	tdata.target.ptr = msg->obj_id.binder;
	tdata.code = msg->code;
	tdata.flags = msg->flags;
	tdata.sender_pid = msg->sender_pid;
	tdata.sender_euid = msg->sender_euid;
	
	tdata.data_size = mbuf->data_size;
	tdata.offsets_size = mbuf->offsets_size;
	
	tdata.data.ptr.buffer = data_buf;
	tdata.data.ptr.offsets = data_buf + (mbuf->offsets - mbuf->data);

	p = mbuf->offsets;
	ep = mbuf->offsets + mbuf->offsets_size;
	while (p < ep) {
		bp = (struct flat_binder_object *)(mbuf->data + *p++);

		r = bcmd_read_flat_obj(proc, thread, bp);
		if (r < 0)
			return r;
	}

	if (put_user(cmd, (uint32_t *)buf) ||
	    copy_to_user(buf + sizeof(cmd), &tdata, sizeof(tdata)) ||
	    copy_to_user(data_buf, mbuf->data, mbuf->data_size))
		return -EFAULT;

	if (msg->type == BC_TRANSACTION) {
		if (!(msg->flags & TF_ONE_WAY))
			list_add(&msg->list, &thread->incoming_transactions);		// compat/TODO: shouldn't it be tail?
	} else {
		if (thread->pending_replies > 0)
			thread->pending_replies--;
		kfree(msg);
	}

	*pmsg = NULL;
	return (data_off + data_size);
}

static long bcmd_read_notifier(struct binder_proc *proc, struct binder_thread *thread, struct bcmd_msg **pmsg, void __user *buf, unsigned long size)
{
	struct bcmd_msg *msg = *pmsg;
	struct binder_notifier *notifier;
	struct binder_obj *obj;
	int r = 0;

	obj = _binder_find_obj(proc, proc->queue, msg->obj_id.binder);
	if (!obj)
		return -EFAULT;

	if (msg->type == BC_REQUEST_DEATH_NOTIFICATION) {
		// TODO: check duplication?
		notifier = kmalloc(sizeof(*notifier), GFP_KERNEL);
		if (!notifier)
			return -ENOMEM;
		notifier->event = BINDER_EVT_OBJ_DEAD;	// TODO: the only event (hard-coded)
		notifier->cookie = msg->cookie;
		notifier->notify_queue = msg->reply_queue;

		spin_lock(&obj->lock);
		list_add_tail(&notifier->list, &obj->notifiers);
		spin_unlock(&obj->lock);
	} else {
		struct binder_notifier *next;
		uint32_t cmd = BR_CLEAR_DEATH_NOTIFICATION_DONE;
		int found = 0;

		if (size < sizeof(cmd))
			return -ENOSPC;

		spin_lock(&obj->lock);
		list_for_each_entry_safe(notifier, next, &obj->notifiers, list) {
			if (notifier->event == BINDER_EVT_OBJ_DEAD &&
			    notifier->cookie == msg->cookie &&
			    notifier->notify_queue == msg->reply_queue) {
				found = 1;
				list_del(&notifier->list);
				break;
			}
		}
		spin_unlock(&obj->lock);

		if (found) {
			kfree(notifier);
			if (put_user(cmd, (uint32_t *)buf))
				return -EFAULT;
			else
				r = sizeof(cmd);
		}
	}

	kfree(msg);
	*pmsg = NULL;
	return r;
}

static long bcmd_read_dead_binder(struct binder_proc *proc, struct binder_thread *thread, struct bcmd_msg **pmsg, void __user *buf, unsigned long size)
{
	uint32_t cmd = BR_DEAD_BINDER;

	if (size < sizeof(cmd))
		return -ENOSPC;

	if (put_user(cmd, (uint32_t *)buf))
		return -EFAULT;

	kfree(*pmsg);
	*pmsg = NULL;
	return sizeof(cmd);
}

static int bcmd_spawn_on_busy(struct binder_proc *proc, void __user *buf, unsigned long size)
{
	uint32_t cmd = BR_SPAWN_LOOPER;
	int n, num_loopers, busy_loopers;

	if (size < sizeof(cmd))
		return 0;

	n = msg_queue_size(proc->queue);

	// smp_rmb();
	num_loopers = atomic_read(&proc->num_loopers) + atomic_read(&proc->requested_loopers);
	busy_loopers = atomic_read(&proc->busy_loopers);

	if (num_loopers < (busy_loopers + n) && num_loopers < proc->max_threads) {
		if (put_user(cmd, (uint32_t *)buf))
			return -EFAULT;

		atomic_inc(&proc->requested_loopers);
		return sizeof(cmd);
	}

	return 0;
}

static long binder_thread_read(struct binder_proc *proc, struct binder_thread *thread, void __user *buf, unsigned long size)
{
	struct bcmd_msg *msg = NULL;
	struct msg_queue *q;
	void __user *p = buf;
	long n;

	if (thread->last_error) {
		if (size >= sizeof(uint32_t)) {
			if (put_user(thread->last_error, (uint32_t *)p))
				return -EFAULT;
			thread->last_error = 0;
			p += sizeof(uint32_t);
			size -= n;
		}
	}

	n = bcmd_spawn_on_busy(proc, p, size);
	if (n > 0) {
		p += n;
		size -= n;
	} else if (n < 0)
		return n;

	atomic_inc(&proc->busy_loopers);

	while (size >= sizeof(uint32_t)) {
		if (thread->pending_replies || !msg_queue_empty(thread->queue))
			q = thread->queue;
		else
			q = proc->queue;
		n = _bcmd_read_msg(q, &msg);
		if (n < 0)
			goto clean_up;

		switch (msg->type) {
			case BC_TRANSACTION:
			case BC_REPLY:
				n = bcmd_read_transaction(proc, thread, &msg, p, size);
				break;

			case BC_REQUEST_DEATH_NOTIFICATION:
			case BC_CLEAR_DEATH_NOTIFICATION:
				n = bcmd_read_notifier(proc, thread, &msg, p, size);
				break;

			case BR_DEAD_BINDER:
				n = bcmd_read_dead_binder(proc, thread, &msg, p, size);
				break;

			default:
				kfree(msg);
				n = -EFAULT;
				goto clean_up;
		}

		if (msg && (n != -ENOSPC))
			kfree(msg);

		if (n > 0) {
			p += n;
			size -= n;
		} else if (n < 0) {
			if (n == -ENOSPC) {
				if (msg) {	// put msg back to the queue. TODO: ugly
					n = _bcmd_write_msg_head(q, msg);
					if (n < 0) {
						kfree(msg);
						goto clean_up;
					}
				}
				n = 0;		// TODO: review no-space handling
			}
			break;
		}
	}

clean_up:
	atomic_dec(&proc->busy_loopers);

	if (n < 0)
		return n;
	else
		return (p - buf);
}

static inline int cmd_write_read(struct binder_proc *proc, struct binder_thread *thread, struct binder_write_read *bwr)
{
	int r;

	if (bwr->write_size > 0) {
		r = binder_thread_write(proc, thread, (void __user *)bwr->write_buffer + bwr->write_consumed, bwr->write_size);
		if (r < 0)
			return r;
		bwr->write_consumed += r;
	}

	if (bwr->read_size > 0) {
		r = binder_thread_read(proc, thread, (void __user *)bwr->read_buffer + bwr->read_consumed, bwr->read_size);
		if (r < 0)
			return r;
		bwr->read_consumed += r;
	}

	return 0;
}

static inline int cmd_thread_exit(struct binder_proc *proc, struct binder_thread *thread)
{
	return binder_free_thread(proc, thread);
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

	if (context_mgr_uid == -1)
		context_mgr_uid = current->cred->euid;
	else if (context_mgr_uid != current->cred->euid)
		return -EPERM;

	context_mgr_obj = binder_new_obj(proc, NULL);
	if (!context_mgr_obj)
		return -ENOMEM;

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

	if (context_mgr_obj && context_mgr_obj->obj_id.owner == proc->queue) 
		context_mgr_obj = NULL;

	// TODO: assume no more threads running
	// TODO: make sure existing referencing context_mgr_obj is safe
	binder_free_proc(proc);
	return 0;
}

static long binder_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct binder_proc *proc = filp->private_data;
	struct binder_thread *thread;
	unsigned int size = _IOC_SIZE(cmd);
	void __user *ubuf = (void __user *)arg;
	int r;

	thread = binder_get_thread(proc, filp);
	if (!thread)
		return -ENOMEM;

	switch (cmd) {
		case BINDER_WRITE_READ: {
			struct binder_write_read bwr;

			if (size != sizeof(bwr))
				return -EINVAL;
			if (copy_from_user(&bwr, ubuf, sizeof(bwr)))
				return -EFAULT;

			r = cmd_write_read(proc, thread, &bwr);
			if (r < 0)
				return r;

			if (copy_to_user(ubuf, &bwr, sizeof(bwr)))
				return -EFAULT;
			return 0;
		}

		case BINDER_THREAD_EXIT:
			return cmd_thread_exit(proc, thread);

		case BINDER_SET_MAX_THREADS: {
			int max_threads;

			if (size != sizeof(int))
				return -EINVAL;
			if (get_user(max_threads, (int *)ubuf))
				return -EFAULT;

			return cmd_set_max_threads(proc, max_threads);
		}

		case BINDER_VERSION:
			if (size != sizeof(struct binder_version))
				return -EINVAL;
			if (put_user(BINDER_CURRENT_PROTOCOL_VERSION, &((struct binder_version *)ubuf)->protocol_version))
				return -EFAULT;
			return 0;

		case BINDER_SET_CONTEXT_MGR:
			return cmd_set_context_mgr(proc);

		default:
			return -EINVAL;
	}
}

static unsigned int binder_poll(struct file *filp, poll_table *p)
{
	struct binder_proc *proc = filp->private_data;
	struct binder_thread *thread;

	thread = binder_get_thread(proc, filp);
	if (!thread)
		return -ENOMEM;

	msg_queue_poll_wait_read(proc->queue, filp, p);
	msg_queue_poll_wait_read(thread->queue, filp, p);

	if (thread->last_error ||
            !msg_queue_empty(thread->queue) ||
            (!thread->pending_replies && msg_queue_size(proc->queue) > 0))
		return POLLIN | POLLRDNORM;

	// TODO: consider POLLOUT case as write can block too (not compat)
	return 0;
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
	int r;

	r = misc_register(&binder_miscdev);
	if (r < 0)
		return r;
	return 0;
}

static void __exit binder_exit(void)
{
	misc_deregister(&binder_miscdev);
}

module_init(binder_init);
module_exit(binder_exit);
MODULE_LICENSE("GPL v2");
