#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/kref.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>

#include "msg_queue.h"
#include "binder.h"


#define MAX_TRANSACTION_SIZE			8192
#define TRANSACTION_HASH_BUCKET_SIZE		16


struct binder_thread {
	struct rb_node rb_node;
	pid_t pid;
	struct msg_queue *queue;

	int non_block;

	unsigned int num_pending;
	struct list_head pending_transactions[TRANSACTION_HASH_BUCKET_SIZE];
};

struct binder_proc {
	pid_t pid;		// task_tgid_vnr(current); 

	spinlock_t lock;
	struct rb_root thread_tree;

	spinlock_t obj_lock;
	struct rb_root obj_tree;

	struct msg_queue *queue;
};

struct binder_obj {
	void __user *user_ptr;
	void __user *user_cookie;

	atomic_t refs;

	struct msg_queue *owner_queue;
	struct rb_node rb_node;

	struct msg_queue **notifiers;
};

struct bcmd_data_handle {
	uint32_t handle;
	uint32_t cookie;
};

struct bcmd_data_ref {
	uint32_t obj_id;
};

struct bcmd_data_obj {
	uint32_t obj_id;
	uint32_t cookie;
};

#define bcmd_data_transaction	binder_transaction_data

struct bcmd_msg_buf {
	void *data;
	size_t data_size;

	void *offsets;
	size_t offsets_size;
}

struct bcmd_msg {
	size_t handle;
	void *cookie;
	unsigned int code;
	struct bcmd_msg_buf *buf;

	pid_t sender_pid;
	uid_t sender_euid;

	struct msg_queue *reply_queue;
	struct list_head list;
};



static inline struct binder_thread *binder_new_thread(pid_t pid)
{	
	struct binder_thread *thread;
	int i;

	thread = kmalloc(sizeof(*thread), GFP_KERNEL);
	if (!thread)
		return NULL;

	thread->pid = pid;
	thread->queue = create_msg_queue(0, thread->non_block, free_transaction);
	if (!thread->queue) {
		kfree(thread);
		return NULL;
	}

	thread->non_block = 0;

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
	pid_t pid = current->pid;

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

	thread = binder_new_thread(pid);
	if (!thread)
		return NULL;

	if (filp->f_flags & O_NONBLOCK)
		thread->non_block = 1;

	spin_lock(&proc->lock);
	rb_link_node(&thread->rb_node, parent, p);
	rb_insert_color(&thread->rb_node, &proc->thread_tree);
	spin_unlock(&proc->lock);

	return thread;
}

static struct bcmd_msg *binder_alloc_msg(size_t data_size, size_t offsets_size)
{
	struct bcmd_msg *msg;
	void *p;

	msg_size = ALIGN(sizeof(*msg), sizeof(void *));
	buf_size = ALIGN(data_size, sizeof(void *)) + ALIGN(offsets_size, sizeof(void *));

	msg = kmalloc(msg_size + buf_size, GFP_KERNEL);
	if (!p)
		return NULL;

	msg->buf = (struct bcmd_msg_buf *)((void *)msg + msg_size);
	INIT_LIST_HEAD(&msg->list);

	return msg;
}

static int bcmd_transaction(struct binder_proc *proc, struct binder_thread *thread, struct bcmd_data_transaction *tdata)
{
	struct binder_obj *obj;
	unsigned long obj_id = tdata->target.handle;
	struct msg_queue *q;
	size_t data_size, offsets_size;
	uint32_t err;

	obj = binder_get_obj(proc, obj_id);
	if (!obj) {
		err = BR_FAILED_REPLY;
		goto failed_obj;
	}

	q = obj->owner_queue;
	if (get_msg_queue(q) < 0) {
		err = BR_DEAD_REPLY;
		goto failed_queue;
	}

	msg = binder_alloc_msg(tdata->data_size, tdata->offsets_size);
	if (!msg) {
		err = BR_FAILED_REPLY;
		goto failed_msg;
	}

	if (!bcmd_load_msg_buf(proc, thread, msg->buf, tdata)) {
		err = BR_FAILED_REPLY;
		goto failed_load;
	}

	msg->handle = obj->handle;
	msg->cookie = obj->cookie;
	msg->code = tdata->code;
	msg->flags = tdata->flags;
	msg->sender_pid = proc->pid;
	msg->sender_euid = current->cred->euid;
	msg->priority = task_nice(current);
	msg->reply_queue = q; 

	if (write_msg_queue(q, msg) < 0) {
		err = BR_DEAD_REPLY;
		goto failed_write;
	}

	if (tdata->flags & TF_ONE_WAY) {
		// push transaction id onto pending stack
	}

	return 0;

failed_write:
	kfree(msg);
failed_load:
failed_msg:
	put_msg_queue(q);
failed_queue:
	binder_put_obj(obj);
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

				if ((p + sizeof(tdata)) > ep || copy_from_user(&tr, p, sizeof(tdata)))
					return -EFAULT;
				p += sizeof(tdata);

				if (tdata->data_size > 0 || tdata->offsets_size > 0) {
					size_t objs_size = tdata->offsets_size / sizeof(size_t) * sizeof(struct flat_binder_object);

					if (objs_size + tdata->offsets_size > tdata->data_size || tdata->data_size > MAX_TRANSACTION_SIZE)
						return -EINVAL;
				}

				if (bcmd == BC_TRANSACTION)
					err += bcmd_transaction(proc, thread, tdata);
				else
					err += bcmd_reply(proc, thread, tdata);
				break;
			}

			case BC_INCREFS:
			case BC_ACQUIRE: 
			case BC_DECREFS:
			case BC_RELEASE: {
				struct bcmd_data_ref ref;

				if ((p + sizeof(ref)) > ep || copy_from_user(&ref, p, sizeof(ref)))
					return -EFAULT;
				p += sizeof(ref);

				if (bcmd == BC_INCREFS || bcmd == BC_ACQUIRE)
					err += bcmd_inc_ref(thread, &ref);
				else
					err += bcmd_dec_ref(thread, &ref);

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

static long binder_thread_read(struct binder_proc *proc, struct binder_thread *thread, void __user *buf, unsigned long size)
{
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

static inline int cmd_set_max_thread(struct binder_proc *proc)
{
}

static inline int cmd_set_context_mgr(struct binder_proc *proc)
{
}

static long binder_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct binder_proc *proc = filp->private_data;
	struct binder_thread *thread;
	unsigned int size = _IOC_SIZE(cmd);
	void __user *ubuf = (void __user *)arg;

	thread = binder_get_thread(proc, filp);
	if (unlikely(!thread))
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
