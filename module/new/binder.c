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
#include <linux/file.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/poll.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>

#include <asm/atomic.h>

#include "msg_queue.h"
#include "binder.h"
#include "inst.h"


#define MAX_TRANSACTION_SIZE			4000
#define OBJ_HASH_BUCKET_SIZE			128
#define MSG_BUF_ALIGN(n)			(((n) & (sizeof(void *) - 1)) ? ALIGN((n), sizeof(void *)) : (n))


enum {	// compat: review looper idea
	BINDER_LOOPER_STATE_INVALID     = 0x00,
	BINDER_LOOPER_STATE_REGISTERED  = 0x01,
	BINDER_LOOPER_STATE_ENTERED     = 0x02,
	BINDER_LOOPER_STATE_READY       = 0x03		// compat
};

typedef enum {
	BINDER_EVT_OBJ_DEAD = 1,
} binder_event_t;


struct binder_proc {
	spinlock_t lock;
	struct rb_root thread_tree;

	spinlock_t obj_lock;
	struct rb_root obj_tree;
	struct hlist_head obj_hash[OBJ_HASH_BUCKET_SIZE];
	unsigned long obj_seq;

	struct msg_queue *queue;

	pid_t pid;

	int max_threads;
	atomic_t num_loopers, busy_loopers, requested_loopers;

	struct dentry *proc_dir, *thread_dir, *obj_dir;
	struct list_head garbage_list;	// garbage collected when proc is released
};

struct binder_thread {
	pid_t pid;

	struct rb_node rb_node;
	struct msg_queue *queue;

	int state;
	int non_block;
	unsigned int last_error;

	int pending_replies;
	struct list_head incoming_transactions;

	struct dentry *info_node;

#ifdef KERNEL_INSTRUMENTING
	struct timeval __inst_copies[4];
#endif
};

struct binder_notifier {
	struct list_head list;
	int event;
	void *cookie;
	struct msg_queue *notify_queue;
};

struct binder_obj {
	void *owner;
	void *binder;
	void *cookie;

	struct rb_node rb_node;

	unsigned long ref;
	struct hlist_node hash_node;

	spinlock_t lock;		// used for notifiers only
	struct list_head notifiers;	// TODO: slow deletion

	struct dentry *info_node;
};

#define bcmd_transaction_data	binder_transaction_data

struct bcmd_notifier_data {
	long handle;
	void *cookie;
};

struct bcmd_ref_return {
	uint32_t cmd;
	void *binder;
	void *cookie;
};

struct bcmd_msg_buf {
	uint8_t *data;
	uint8_t *offsets;

	size_t data_size;
	size_t offsets_size;
	size_t buf_size;

	struct msg_queue *owners[0];	// owners of the flatten objects
};

struct bcmd_msg {
	struct list_head list;

	void *binder;
	void *cookie;

	unsigned int type;		// compat: review all data types in/out of the ioctl
	unsigned int code;
	unsigned int flags;

	struct bcmd_msg_buf *buf;

	pid_t sender_pid;
	uid_t sender_euid;

	struct msg_queue *reply_queue;
};

struct debugfs_priv {
	struct msg_queue *owner;
	struct binder_proc *proc;
	unsigned long data;
	struct list_head list;
};


static struct binder_obj *context_mgr_obj;	// compat: is context mgr necessary?
static uid_t context_mgr_uid = -1;

static struct dentry *debugfs_root;


static struct debugfs_priv *debugfs_new_proc(struct binder_proc *proc);
static struct debugfs_priv *debugfs_new_thread(struct binder_proc *proc, struct binder_thread *thread);
static struct debugfs_priv *debugfs_new_obj(struct binder_proc *proc, struct binder_obj *obj);


static inline int binder_cmp(void *owner0, void *binder0, void *owner1, void *binder1)
{
	ssize_t sign;

	if ((sign = owner0 - owner1))
		return (sign > 0) ? 1 : -1;

	if ((sign = binder0 - binder1))
		return (sign > 0) ? 1 : -1;

	return 0;
}

static struct binder_obj *binder_find_obj(struct binder_proc *proc, void *owner, void *binder)
{
	struct rb_node **p = &proc->obj_tree.rb_node;
	struct rb_node *parent = NULL;
	struct binder_obj *obj;
	int r;

	spin_lock(&proc->obj_lock);
	while (*p) {
		parent = *p;
		obj = rb_entry(parent, struct binder_obj, rb_node);

		r = binder_cmp(owner, binder, obj->owner, obj->binder);
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

static inline struct binder_obj *binder_find_my_obj(struct binder_proc *proc, void *binder)
{
	return binder_find_obj(proc, proc->queue, binder);
}

static struct binder_obj *binder_find_obj_by_ref(struct binder_proc *proc, unsigned long ref)
{
	struct binder_obj *obj;
	struct hlist_head *head;
	struct hlist_node *node;

	spin_lock(&proc->obj_lock);

	head = &proc->obj_hash[ref % OBJ_HASH_BUCKET_SIZE];
	hlist_for_each_entry(obj, node, head, hash_node) {
		if (obj->ref == ref) {
			spin_unlock(&proc->obj_lock);
			return obj;
		}
	}

	spin_unlock(&proc->obj_lock);
	return NULL;
}

static struct binder_obj *_binder_new_obj(struct binder_proc *proc, void *owner, void *binder, void *cookie)
{
	struct rb_node **p = &proc->obj_tree.rb_node;
	struct rb_node *parent = NULL;
	struct binder_obj *obj, *new_obj;
	int r;
	struct debugfs_priv *priv;

	new_obj = kmalloc(sizeof(*obj), GFP_KERNEL);
	if (!new_obj)
		return NULL;

	new_obj->owner = owner;
	new_obj->binder = binder;
	new_obj->cookie = cookie;
	spin_lock_init(&new_obj->lock);
	INIT_LIST_HEAD(&new_obj->notifiers);

	spin_lock(&proc->obj_lock);
	while (*p) {
		parent = *p;
		obj = rb_entry(parent, struct binder_obj, rb_node);

		r = binder_cmp(owner, binder, obj->owner, obj->binder);
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

	new_obj->ref = proc->obj_seq++;
	hlist_add_head(&new_obj->hash_node, &proc->obj_hash[new_obj->ref % OBJ_HASH_BUCKET_SIZE]);

	spin_unlock(&proc->obj_lock);

	if (!(priv = debugfs_new_obj(proc, new_obj))) {
		spin_lock(&proc->obj_lock);
		rb_erase(&new_obj->rb_node, &proc->obj_tree);
		hlist_del(&new_obj->hash_node);
		spin_unlock(&proc->obj_lock);
		kfree(new_obj);
		return NULL;
	}
	spin_lock(&proc->lock);
	list_add(&priv->list, &proc->garbage_list);
	spin_unlock(&proc->lock);

	return new_obj;
}

static inline struct binder_obj *binder_new_obj(struct binder_proc *proc, void *binder, void *cookie)
{
	return _binder_new_obj(proc, proc->queue, binder, cookie);
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
	size_t num_objs, msg_size, msg_buf_size, buf_size;
	struct bcmd_msg *msg;
	struct bcmd_msg_buf *mbuf;

	num_objs = offsets_size / sizeof(size_t);
	msg_buf_size = sizeof(*mbuf) + num_objs * sizeof(struct msg_queue *);
	msg_size = sizeof(*msg) + msg_buf_size;
	buf_size = msg_size + MSG_BUF_ALIGN(data_size) + MSG_BUF_ALIGN(offsets_size);

	msg = kmalloc(buf_size, GFP_KERNEL);
	if (!msg)
		return NULL;

	mbuf = (struct bcmd_msg_buf *)((unsigned char *)msg + sizeof(*msg));
	mbuf->data = (unsigned char *)msg + msg_size;
	mbuf->offsets = (unsigned char *)mbuf->data + MSG_BUF_ALIGN(data_size);

	mbuf->data_size = data_size;
	mbuf->offsets_size = offsets_size;
	mbuf->buf_size = buf_size;

	msg->buf = mbuf;
	return msg;
}

static struct bcmd_msg *binder_realloc_msg(struct bcmd_msg *msg, size_t data_size, size_t offsets_size)
{
	size_t num_objs, msg_size, msg_buf_size, buf_size;
	struct bcmd_msg_buf *mbuf = msg->buf;

	num_objs = offsets_size / sizeof(size_t);
	msg_buf_size = sizeof(*mbuf) + num_objs * sizeof(struct msg_queue *);
	msg_size = sizeof(*msg) + msg_buf_size;
	buf_size = msg_size + MSG_BUF_ALIGN(data_size) + MSG_BUF_ALIGN(offsets_size);

	if (mbuf->buf_size >= buf_size) {
		mbuf->data = (unsigned char *)msg + msg_size;
		mbuf->offsets = (unsigned char *)mbuf->data + MSG_BUF_ALIGN(data_size);

		mbuf->data_size = data_size;
		mbuf->offsets_size = offsets_size;
		return msg;
	}

	kfree(msg);
	return binder_alloc_msg(data_size, offsets_size);
}

void _hexdump(const void *buf, unsigned long size)
{
	int col = 0, off = 0, n = 0;
	unsigned char *p = (unsigned char *)buf;
	char cbuf[64];

	while (size--) {
		if (!col)
			printk("\t%08x:", off);

		printk(" %02x", *p);
		cbuf[n++] = (*p >= 0x20 && *p < 0x7f) ? (char)*p : ' ';
		cbuf[n++] = ' ';

		p++;
		off++;
		col++;

		if (!(col % 16)) {
			cbuf[n] = '\0';
			printk("    %s\n", cbuf);
			n = 0;
			col = 0;
		} else if (!(col % 4))
			printk("  ");
	}

	cbuf[n] = '\0';
	if (col % 16)
		printk("    %s\n\n", cbuf);
	else
		printk("    %s\n", cbuf);
}

void _dump_msg(struct bcmd_msg *msg)
{
	printk("\tbinder %p, cookie %p, type %u, code %u, flags %u, uid %d, pid %d, queue %p\n", 
		msg->binder, msg->cookie, msg->type, msg->code, msg->flags, msg->sender_pid, msg->sender_euid, msg->reply_queue);
	if (msg->buf) {
		struct bcmd_msg_buf *mbuf = msg->buf;

		if (mbuf->data_size > 0) {
			printk("\t data size %u\n", mbuf->data_size);
			_hexdump(mbuf->data, mbuf->data_size);

			if (mbuf->offsets_size > 0) {
				printk("\t offsets size %u\n", mbuf->offsets_size);
				_hexdump(mbuf->offsets, mbuf->offsets_size);
			}
		}
	}
}

static void msg_queue_release(struct msg_queue *q, void *data)
{
	struct list_head *entry;
	struct bcmd_msg *msg;

	while ((entry = msg_queue_pop(q))) {
		msg = container_of(entry, struct bcmd_msg, list);

		if (msg->type == BC_TRANSACTION) {
			msg->type = BR_DEAD_BINDER;
			if (!bcmd_write_msg(msg->reply_queue, msg))
				continue;
		}

		kfree(msg);
	}
}

static void proc_msg_queue_release(struct msg_queue *q, void *data)
{
	struct binder_proc *proc = data;
	struct debugfs_priv *priv, *next;

	msg_queue_release(q, NULL);

	// safe to do garbage collection now
	list_for_each_entry_safe(priv, next, &proc->garbage_list, list) {
		list_del(&priv->list);
		kfree(priv);
	}

	kfree(proc);
}

static struct binder_proc *binder_new_proc(struct file *filp)
{
	struct binder_proc *proc;
	int i;
	struct debugfs_priv *priv;

	proc = kmalloc(sizeof(*proc), GFP_KERNEL);
	if (!proc)
		return NULL;

	proc->queue = create_msg_queue(0, proc_msg_queue_release, proc);
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

	for (i = 0; i < sizeof(proc->obj_hash) / sizeof(proc->obj_hash[0]); i++)
		INIT_HLIST_HEAD(&proc->obj_hash[i]);
	proc->obj_seq = 1;	// compat: context_mgr_node starts 0?

	spin_lock_init(&proc->obj_lock);
	proc->obj_tree.rb_node = NULL;

	INIT_LIST_HEAD(&proc->garbage_list);

	if (!(priv = debugfs_new_proc(proc))) {
		// the queue release handle will free proc struct
		free_msg_queue(proc->queue);
		return NULL;
	}
	list_add(&priv->list, &proc->garbage_list);

	return proc;
}

static struct binder_thread *binder_new_thread(struct binder_proc *proc, struct file *filp, pid_t pid)
{	
	struct binder_thread *new_thread, *thread;
	struct rb_node **p = &proc->thread_tree.rb_node;
	struct rb_node *parent = NULL;
	struct debugfs_priv *priv;

	new_thread = kmalloc(sizeof(*new_thread), GFP_KERNEL);
	if (!new_thread)
		return NULL;

	new_thread->queue = create_msg_queue(0, msg_queue_release, NULL);
	if (!new_thread->queue || get_msg_queue(proc->queue) < 0) {
		kfree(new_thread);
		return NULL;
	}

	new_thread->pid = pid;
	new_thread->state = 0;
	new_thread->last_error = 0;
	new_thread->non_block = (filp->f_flags & O_NONBLOCK) ? 1 : 0;	// compat
	new_thread->pending_replies = 0;
	INIT_LIST_HEAD(&new_thread->incoming_transactions);

	if (!(priv = debugfs_new_thread(proc, new_thread))) {
		free_msg_queue(new_thread->queue);
		kfree(new_thread);
		return NULL;
	}

	spin_lock(&proc->lock);
	while (*p) {
		parent = *p;
		thread = rb_entry(parent, struct binder_thread, rb_node);

		if (pid < thread->pid)
			p = &(*p)->rb_left;
		else if (pid > thread->pid)
			p = &(*p)->rb_right;
		else {
			BUG();
			spin_unlock(&proc->lock);
			return thread;
		}
	}

	rb_link_node(&new_thread->rb_node, parent, p);
	rb_insert_color(&new_thread->rb_node, &proc->thread_tree);

	list_add(&priv->list, &proc->garbage_list);
	spin_unlock(&proc->lock);

	return new_thread;
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

	return binder_new_thread(proc, filp, pid);
}

static int binder_free_thread(struct binder_proc *proc, struct binder_thread *thread)
{
	struct bcmd_msg *msg, *next;

	debugfs_remove(thread->info_node);

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

	put_msg_queue(proc->queue);
	kfree(thread);
	return 0;
}

static int binder_free_obj(struct binder_proc *proc, struct binder_obj *obj)
{
	debugfs_remove(obj->info_node);

	if (obj->owner == proc->queue) {
		struct binder_notifier *notifier, *next;
		struct bcmd_msg *msg = NULL;

		list_for_each_entry_safe(notifier, next, &obj->notifiers, list) {
			list_del(&notifier->list);

			if (!msg) {
				msg = binder_alloc_msg(0, 0); // TODO: ugly
				if (!msg) {
					kfree(obj);
					return -ENOMEM;
				}
			}

			msg->type = BR_DEAD_BINDER;
			msg->binder = obj->binder;
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

	disable_msg_queue(proc->queue);

	while ((n = rb_first(&proc->thread_tree))) {
		thread = rb_entry(n, struct binder_thread, rb_node);
		r = binder_free_thread(proc, thread);
		if (r < 0)
			return r;
	}

	spin_lock(&proc->obj_lock);
	while ((n = rb_first(&proc->obj_tree))) {
		obj = rb_entry(n, struct binder_obj, rb_node);

		rb_erase(n, &proc->obj_tree);
		hlist_del(&obj->hash_node);

		r = binder_free_obj(proc, obj);
		if (r < 0) {
			spin_unlock(&proc->obj_lock);
			return r;
		}
	}
	spin_unlock(&proc->obj_lock);

	debugfs_remove_recursive(proc->proc_dir);

	free_msg_queue(proc->queue);
	return 0;
}

static int bcmd_write_flat_obj(struct binder_proc *proc, struct binder_thread *thread, struct flat_binder_object *bp, struct msg_queue **owner)
{
	struct binder_obj *obj;
	struct bcmd_msg *msg; 
	struct file *file;
	unsigned long type = bp->type;

	switch (type) {
		case BINDER_TYPE_BINDER:
		case BINDER_TYPE_WEAK_BINDER:
			obj = binder_find_my_obj(proc, bp->binder);
			if (!obj) {
				obj = binder_new_obj(proc, bp->binder, bp->cookie);
				if (!obj)
					return -ENOMEM;

				// compat: notify writer we are referencing this object
				msg = binder_alloc_msg(0, 0);
				if (!msg)
					return -ENOMEM;

				msg->type = BR_ACQUIRE;
				msg->binder = bp->binder;
				msg->cookie = bp->cookie;
				_bcmd_write_msg(thread->queue, msg);
			} else if (bp->cookie != obj->cookie)
				return -ENOMEM;

			bp->type = (type == BINDER_TYPE_BINDER) ? BINDER_TYPE_HANDLE : BINDER_TYPE_WEAK_HANDLE;
			*owner = obj->owner;
			break;

		case BINDER_TYPE_HANDLE:
		case BINDER_TYPE_WEAK_HANDLE:
			obj = binder_find_obj_by_ref(proc, bp->handle);
			if (!obj)
				return -EINVAL;

			bp->binder = obj->binder;
			bp->cookie = obj->cookie;
			*owner = obj->owner;
			break;

		case BINDER_TYPE_FD:
			file = fget(bp->handle);
			if (!file)
				return -EINVAL;
			bp->binder = file;
			*owner = NULL;		// unused
			break;

		default: 
			return -EINVAL;
	}

	return 0;
}

static int bcmd_read_flat_obj(struct binder_proc *proc, struct binder_thread *thread, struct flat_binder_object *bp, struct msg_queue *owner)
{
	struct binder_obj *obj;
	struct file *file;
	int fd;
	unsigned long type = bp->type;

	switch (type) {
		case BINDER_TYPE_HANDLE:
		case BINDER_TYPE_WEAK_HANDLE:
			obj = binder_find_obj(proc, owner, bp->binder);
			if (obj) {
				if (owner == proc->queue) {
					bp->type = (type == BINDER_TYPE_HANDLE) ? BINDER_TYPE_BINDER : BINDER_TYPE_WEAK_BINDER;
					bp->cookie = obj->cookie;	// compat
				}
			} else {
				obj = _binder_new_obj(proc, owner, bp->binder, bp->cookie);
				if (!obj)
					return -ENOMEM;
			}

			bp->handle = (long)obj->ref;
			break;

		case BINDER_TYPE_FD:
			file = (struct file *)bp->binder;
			fd = get_unused_fd();	// compat/TODO: O_CLOEXEC
			if (fd < 0) {
				fput(file);
				return -ENOMEM;
			}
			fd_install(fd, file);
			bp->handle = fd;	// TODO: fput() when free unread msg!!!
			break;

		/* No more these types */
		case BINDER_TYPE_BINDER:
		case BINDER_TYPE_WEAK_BINDER:

		default: 
			return -EFAULT;
	}

	return 0;
}

static int bcmd_write_msg_buf(struct binder_proc *proc, struct binder_thread *thread, struct bcmd_msg_buf *mbuf, struct bcmd_transaction_data *tdata)
{
	size_t *p, *ep, off;
	struct flat_binder_object *bp;
	int n, r;

	if (copy_from_user(mbuf->data, tdata->data.ptr.buffer, mbuf->data_size))
		return -EFAULT;

	if (!mbuf->offsets_size)
		return 0;
	if (copy_from_user(mbuf->offsets, tdata->data.ptr.offsets, mbuf->offsets_size))
		return -EFAULT;

	n = 0;
	p = (size_t *)mbuf->offsets;
	ep = (size_t *)((unsigned char *)mbuf->offsets + mbuf->offsets_size);
	while (p < ep) {
		off = *p++;
		if (off + sizeof(*bp) > mbuf->data_size)
			return -EINVAL;

		bp = (struct flat_binder_object *)(mbuf->data + off);

		r = bcmd_write_flat_obj(proc, thread, bp, mbuf->owners + n++);
		if (r < 0)
			return r;
	}

	return 0;
}

static int bcmd_write_transaction(struct binder_proc *proc, struct binder_thread *thread, struct bcmd_transaction_data *tdata, uint32_t bcmd)
{
	struct bcmd_msg *msg;
	struct msg_queue *q;
	void *binder, *cookie;
	uint32_t err;

	if (bcmd == BC_TRANSACTION) {
		struct binder_obj *obj;

		if (unlikely(!tdata->target.handle))
			obj = context_mgr_obj;
		else
			obj = binder_find_obj_by_ref(proc, tdata->target.handle);

		if (!obj) {
			err = BR_FAILED_REPLY;
			goto failed_obj;
		}

		msg = binder_alloc_msg(tdata->data_size, tdata->offsets_size);
		if (!msg) {
			err = BR_FAILED_REPLY;
			goto failed_msg;
		}
		INST_RECORD(thread, 1);

		q = obj->owner;
		binder = obj->binder;
		cookie = obj->cookie;
	} else {
		// compat: pop out the top transaction without checking
		if (list_empty(&thread->incoming_transactions)) {
			err = BR_FAILED_REPLY;
			goto failed_transaction;
		}
		msg = list_first_entry(&thread->incoming_transactions, struct bcmd_msg, list);
		list_del(&msg->list);

		q = msg->reply_queue;
		binder = cookie = NULL;		// compat

		msg = binder_realloc_msg(msg, tdata->data_size, tdata->offsets_size);
		if (!msg) {
			err = BR_FAILED_REPLY;
			goto failed_msg;
		}
		INST_RECORD(thread, 1);
	}

	msg->type = bcmd;
	msg->binder = binder;
	msg->cookie = cookie;	// compat: ignore cookie in tdata - strange
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
	//printk("proc %d (tid %d) write %s message:\n", proc->pid, thread->pid, bcmd == BC_REPLY ? "reply" : "transaction");
	//_hexdump(tdata, sizeof(*tdata));
	//_dump_msg(msg);

	INST_ENTRY_COPY(thread, msg->buf->data, "K_IOC", 0);
	INST_ENTRY_COPY(thread, msg->buf->data, "K_ALLOC", 1);
	INST_ENTRY(msg->buf->data, "K_WRITE");
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

	obj = binder_find_obj_by_ref(proc, notifier->handle);
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
	msg->binder = obj->binder;
	msg->cookie = notifier->cookie;
	msg->reply_queue = proc->queue;		// notification sent to the process queue

	if (bcmd_write_msg(obj->owner, msg) < 0) {
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

					if (objs_size > tdata.data_size || tdata.data_size > MAX_TRANSACTION_SIZE)
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

			case BC_INCREFS:
			case BC_ACQUIRE:
			case BC_RELEASE:
			case BC_DECREFS:
			case BC_DEAD_BINDER_DONE:
			case BC_FREE_BUFFER:	// compat: not used
				// TODO: do something?
				p += sizeof(void *);
				break;

			case BC_INCREFS_DONE:
			case BC_ACQUIRE_DONE:
				// TODO: do something?
				p += 2 * sizeof(void *);
				break;

			default:
				printk("unknown binder command %x from process %d\n", bcmd, proc->pid);
				return -EINVAL;
		}
	}

	return p - buf;
}

static long bcmd_read_transaction(struct binder_proc *proc, struct binder_thread *thread, struct bcmd_msg **pmsg, void __user *buf, unsigned long size)
{
	struct bcmd_transaction_data tdata;
	struct bcmd_msg *msg = *pmsg;
	struct bcmd_msg_buf *mbuf = msg->buf;
	uint32_t cmd = (msg->type == BC_TRANSACTION) ? BR_TRANSACTION : BR_REPLY;
	size_t data_off, data_size;

	data_off = sizeof(cmd) + sizeof(tdata);
	data_size = MSG_BUF_ALIGN(mbuf->data_size) + MSG_BUF_ALIGN(mbuf->offsets_size);
	if (data_off + data_size > size)
		return -ENOSPC;

	INST_ENTRY_COPY(thread, mbuf->data, "K_DEQ", 2);

	tdata.target.ptr = msg->binder;
	tdata.code = msg->code;
	tdata.cookie = msg->cookie;
	tdata.flags = msg->flags;
	tdata.sender_pid = msg->sender_pid;
	tdata.sender_euid = msg->sender_euid;

	tdata.data_size = mbuf->data_size;
	tdata.offsets_size = mbuf->offsets_size;

	if (data_size > 0) {
		void __user *data_buf = buf + data_off;

		tdata.data.ptr.buffer = data_buf;

		if (mbuf->offsets_size > 0) {
			size_t *p, *ep;
			struct flat_binder_object *bp;
			int n, r;

			n = 0;
			p = (size_t *)mbuf->offsets;
			ep = (size_t *)(mbuf->offsets + mbuf->offsets_size);
			while (p < ep) {
				bp = (struct flat_binder_object *)(mbuf->data + *p++);

				r = bcmd_read_flat_obj(proc, thread, bp, mbuf->owners[n++]);
				if (r < 0)
					return r;
			}

			tdata.data.ptr.offsets = data_buf + (mbuf->offsets - mbuf->data);
		} else
			tdata.data.ptr.offsets = NULL;

		INST_ENTRY(mbuf->data, "K_COPY");
		if (copy_to_user(data_buf, mbuf->data, data_size))
			return -EFAULT;
	} else
		tdata.data.ptr.buffer = tdata.data.ptr.offsets = NULL;

	if (put_user(cmd, (uint32_t *)buf) ||
	    copy_to_user(buf + sizeof(cmd), &tdata, sizeof(tdata)))
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

	obj = binder_find_my_obj(proc, msg->binder);
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

		if (size < sizeof(cmd) * 2)
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
			if (put_user(cmd, (uint32_t *)buf) || 
			    put_user((uint32_t)msg->cookie, (uint32_t *)((unsigned char *)buf + sizeof(cmd))))
				return -EFAULT;
			else
				r = sizeof(cmd) * 2;
		}
	}

	kfree(msg);
	*pmsg = NULL;
	return r;
}

static long bcmd_read_transaction_complete(struct binder_proc *proc, struct binder_thread *thread, struct bcmd_msg **pmsg, void __user *buf, unsigned long size)
{
	uint32_t cmd = (*pmsg)->type;

	if (size < sizeof(cmd))
		return -ENOSPC;

	if (put_user(cmd, (uint32_t *)buf))
		return -EFAULT;

	kfree(*pmsg);
	*pmsg = NULL;
	return sizeof(cmd);
}

static long bcmd_read_dead_binder(struct binder_proc *proc, struct binder_thread *thread, struct bcmd_msg **pmsg, void __user *buf, unsigned long size)
{
	uint32_t cmd = (*pmsg)->type, cookie = (uint32_t)(*pmsg)->cookie;

	if (size < sizeof(cmd) * 2)
		return -ENOSPC;

	if (put_user(cmd, (uint32_t *)buf) || 
	    put_user(cookie, (uint32_t *)((unsigned char *)buf + sizeof(cmd))))
		return -EFAULT;

	kfree(*pmsg);
	*pmsg = NULL;
	return sizeof(cmd) * 2;
}

static long bcmd_read_acquire(struct binder_proc *proc, struct binder_thread *thread, struct bcmd_msg **pmsg, void __user *buf, unsigned long size)
{
	struct bcmd_msg *msg = *pmsg;
	struct bcmd_ref_return cmds[2];

	if (size < sizeof(cmds))
		return -ENOSPC;

	cmds[0].cmd = BR_INCREFS;
	cmds[0].binder = msg->binder;
	cmds[0].cookie = msg->cookie;

	cmds[1].cmd = BR_ACQUIRE;
	cmds[1].binder = msg->binder;
	cmds[1].cookie = msg->cookie;

	if (copy_to_user(buf, cmds, sizeof(cmds)))
		return -EFAULT;

	kfree(*pmsg);
	*pmsg = NULL;
	return sizeof(cmds);
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
	struct msg_queue *q;
	struct bcmd_msg *msg = NULL;
	void __user *p = buf;
	int force_return = 0;
	long n;

	if (thread->last_error) {
		if (size >= sizeof(uint32_t)) {
			if (put_user(thread->last_error, (uint32_t *)p))
				return -EFAULT;
			thread->last_error = 0;
			p += sizeof(uint32_t);
		}
		return p - buf;	// error returned immediately
	}

	n = bcmd_spawn_on_busy(proc, p, size);
	if (n)	// spawn or error returned immediately
		return n;

	atomic_inc(&proc->busy_loopers);

	while (size >= sizeof(uint32_t) && !force_return) {
		if (thread->pending_replies > 0 || !msg_queue_empty(thread->queue))
			q = thread->queue;
		else
			q = proc->queue;

		if (msg_queue_empty(q) && thread->non_block)
			break;

		n = _bcmd_read_msg(q, &msg);
		if (n < 0)
			goto clean_up;

		INST_RECORD(thread, 2);
		switch (msg->type) {
			case BC_TRANSACTION:
			case BC_REPLY:
				n = bcmd_read_transaction(proc, thread, &msg, p, size);
				force_return = 1;
				break;

			case BR_TRANSACTION_COMPLETE:
				n = bcmd_read_transaction_complete(proc, thread, &msg, p, size);
				force_return = 1;
				break;

			case BR_DEAD_BINDER:
				n = bcmd_read_dead_binder(proc, thread, &msg, p, size);
				force_return = 1;
				break;

			case BC_REQUEST_DEATH_NOTIFICATION:
			case BC_CLEAR_DEATH_NOTIFICATION:
				n = bcmd_read_notifier(proc, thread, &msg, p, size);
				if (n > 0)
					force_return = 1;
				break;

			case BR_ACQUIRE:
				n = bcmd_read_acquire(proc, thread, &msg, p, size);
				force_return = 1;
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
	if (context_mgr_obj) 
		return -EBUSY;

	if (context_mgr_uid == -1)
		context_mgr_uid = current->cred->euid;
	else if (context_mgr_uid != current->cred->euid)
		return -EPERM;

	context_mgr_obj = binder_new_obj(proc, NULL, NULL);
	if (!context_mgr_obj)
		return -ENOMEM;

	return 0;
}

static int binder_open(struct inode *nodp, struct file *filp)
{
	struct binder_proc *proc;

	proc = binder_new_proc(filp);
	if (!proc)
		return -ENOMEM;

	filp->private_data = proc;
	return 0;
}

static int binder_release(struct inode *nodp, struct file *filp)
{
	struct binder_proc *proc = filp->private_data;

	if (context_mgr_obj && context_mgr_obj->owner == proc->queue) 
		context_mgr_obj = NULL;

	// TODO: make sure existing referencing context_mgr_obj is safe
	// TODO: assume no more threads running

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

	INST_RECORD(thread, 0);

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
			printk("unknown binder ioctl command %x from process %d\n", cmd, proc->pid);
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
	    (thread->pending_replies < 1 && msg_queue_size(proc->queue) > 0))
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

static int debugfs_proc_info(struct seq_file *seq, void *start)
{	
	struct debugfs_priv *priv = seq->private;
	struct binder_proc *proc;

	if (get_msg_queue(priv->owner) < 0)
		return -ENODEV;

	proc = priv->proc;

	seq_printf(seq, "pid: %d\n", proc->pid);
	seq_printf(seq, "queue: %p\n", proc->queue);
	seq_printf(seq, "obj_seq: %lu\n", proc->obj_seq);
	seq_printf(seq, "max_threads: %d\n", proc->max_threads);
	seq_printf(seq, "num_loopers: %d\n", atomic_read(&proc->num_loopers));
	seq_printf(seq, "busy_loopers: %d\n", atomic_read(&proc->busy_loopers));
	seq_printf(seq, "requested_loopers: %d\n", atomic_read(&proc->requested_loopers));

	put_msg_queue(priv->owner);
	return 0;
}

static int debugfs_thread_info(struct seq_file *seq, void *start)
{
	struct debugfs_priv *priv = seq->private;
	struct binder_proc *proc;
	pid_t pid;
	struct rb_node **p;
	struct rb_node *parent = NULL;
	struct binder_thread *thread;

	if (get_msg_queue(priv->owner) < 0)
		return -ENODEV;

	proc = priv->proc;
	pid = priv->data;
	p = &proc->thread_tree.rb_node;

	spin_lock(&proc->lock);
	while (*p) {
		parent = *p;
		thread = rb_entry(parent, struct binder_thread, rb_node);

		if (pid < thread->pid)
			p = &(*p)->rb_left;
		else if (pid > thread->pid)
			p = &(*p)->rb_right;
		else
			goto seq_show;
	}
	spin_unlock(&proc->lock);

	put_msg_queue(priv->owner);
	return -ENODEV;
	
seq_show:
	seq_printf(seq, "pid: %d\n", thread->pid);
	seq_printf(seq, "queue: %p\n", thread->queue);
	seq_printf(seq, "state: %d\n", thread->state);
	seq_printf(seq, "non_block: %d\n", thread->non_block);
	seq_printf(seq, "last_error: %x\n", thread->last_error);
	seq_printf(seq, "pending_replies: %d\n", thread->pending_replies);
	//TODO: show incoming_transactions

	spin_unlock(&proc->lock);

	put_msg_queue(priv->owner);
	return 0;
}

static int debugfs_obj_info(struct seq_file *seq, void *start)
{
	struct debugfs_priv *priv = seq->private;
	struct binder_proc *proc;
	unsigned long ref;
	struct binder_obj *obj;
	struct hlist_head *head;
	struct hlist_node *node;

	if (get_msg_queue(priv->owner) < 0)
		return -ENODEV;

	proc = priv->proc;
	ref = priv->data;

	spin_lock(&proc->obj_lock);

	head = &proc->obj_hash[ref % OBJ_HASH_BUCKET_SIZE];
	hlist_for_each_entry(obj, node, head, hash_node) {
		if (obj->ref == ref)
			goto seq_show;
	}

	spin_unlock(&proc->obj_lock);

	put_msg_queue(priv->owner);
	return -ENODEV;

seq_show:
	seq_printf(seq, "ref: %lu\n", obj->ref);
	seq_printf(seq, "type: %s\n", (obj->owner == proc->queue) ? "binder" : "handle");
	seq_printf(seq, "owner: %p\n", obj->owner);
	seq_printf(seq, "binder: %p\n", obj->binder);
	seq_printf(seq, "cookie: %p\n", obj->cookie);
	// TODO: show notifiers

	spin_unlock(&proc->obj_lock);

	put_msg_queue(priv->owner);
	return 0;
}

static int debugfs_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, debugfs_proc_info, inode->i_private);
}

static int debugfs_thread_open(struct inode *inode, struct file *file)
{
	return single_open(file, debugfs_thread_info, inode->i_private);
}

static int debugfs_obj_open(struct inode *inode, struct file *file)
{
	return single_open(file, debugfs_obj_info, inode->i_private);
}

static const struct file_operations debugfs_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= debugfs_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release
};

static const struct file_operations debugfs_thread_fops = {
	.owner		= THIS_MODULE,
	.open		= debugfs_thread_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release
};

static const struct file_operations debugfs_obj_fops = {
	.owner		= THIS_MODULE,
	.open		= debugfs_obj_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release
};

static struct debugfs_priv *debugfs_new_proc(struct binder_proc *proc)
{
	struct debugfs_priv *priv;
	struct dentry *d;
	char str[32];

	priv = kmalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		goto no_mem;
	priv->owner = proc->queue;
	priv->proc = proc;

	sprintf(str, "%d", proc->pid);
	d = debugfs_create_file(str, S_IFDIR | S_IRWXU | S_IRUGO | S_IXUGO,
				debugfs_root, proc, NULL);
	if (!d)
		goto no_proc;
	proc->proc_dir = d;

	d = debugfs_create_file("threads", S_IFDIR | S_IRWXU | S_IRUGO | S_IXUGO,
				proc->proc_dir, proc, NULL);
	if (!d)
		goto no_threads;
	proc->thread_dir = d;

	d = debugfs_create_file("objs", S_IFDIR | S_IRWXU | S_IRUGO | S_IXUGO,
				proc->proc_dir, proc, NULL);

	if (!d)
		goto no_objs;
	proc->obj_dir = d;

	d = debugfs_create_file("info", S_IRUGO, proc->proc_dir, priv, &debugfs_proc_fops);
	if (!d)
		goto no_info;

	return priv;

no_info:
	debugfs_remove(proc->obj_dir);
no_objs:
	debugfs_remove(proc->thread_dir);
no_threads:
	debugfs_remove(proc->proc_dir);
no_proc:
	kfree(priv);
no_mem:
	return NULL;
}

static struct debugfs_priv *debugfs_new_thread(struct binder_proc *proc, struct binder_thread *thread)
{
	struct debugfs_priv *priv;
	char str[32];

	priv = kmalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return NULL;

	priv->owner = proc->queue;
	priv->proc = proc;
	priv->data = (unsigned long)thread->pid;

	sprintf(str, "%d", thread->pid);
	thread->info_node = debugfs_create_file(str, S_IRUGO, proc->thread_dir, priv, &debugfs_thread_fops);
	if (!thread->info_node) {
		kfree(priv);
		return NULL;
	}

	return priv;
}

static struct debugfs_priv *debugfs_new_obj(struct binder_proc *proc, struct binder_obj *obj)
{
	struct debugfs_priv *priv;
	char str[32];

	priv = kmalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return NULL;

	priv->owner = proc->queue;
	priv->proc = proc;
	priv->data = obj->ref;

	sprintf(str, "%lu", obj->ref);
	obj->info_node = debugfs_create_file(str, S_IRUGO, proc->obj_dir, priv, &debugfs_obj_fops);
	if (!obj->info_node) {
		kfree(priv);
		return NULL;
	}

	return priv;
}

static int __init binder_debugfs_init(void)
{
	debugfs_root = debugfs_create_dir("binder", NULL);

	if (!debugfs_root) 
		return -ENODEV;
	return 0;
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

	r = binder_debugfs_init();
	if (r < 0)
		return r;

	return 0;
}

static void __exit binder_exit(void)
{
	misc_deregister(&binder_miscdev);

	debugfs_remove(debugfs_root);
}

module_init(binder_init);
module_exit(binder_exit);
MODULE_LICENSE("GPL v2");
