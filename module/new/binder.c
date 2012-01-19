#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/kref.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>

#include "msg_queue.h"
#include "binder.h"


#define TRANSACTION_HASH_BUCKET_SIZE		16


struct binder_transaction {
	struct msg_queue *reply_queue;

	struct binder_transaction_data *msg;
	struct list_head list;
}

struct binder_thread {
	struct rb_node rb_node;
	pid_t pid;
	struct msg_queue *queue;

	unsigned int num_pending;
	struct list_head pending_transactions[TRANSACTION_HASH_BUCKET_SIZE];
}

struct binder_proc {
	spinlock_t lock;
	struct rb_root thread_tree;

	spinlock_t obj_lock;
	struct rb_root obj_tree;

	struct msg_queue *queue;
};

struct binder_object {
	void __user *user_ptr;
	void __user *user_cookie;

	atomic_t refs;

	struct msg_queue *owner_queue;
	struct rb_node rb_node;

	struct msg_queue **notifiers;
};

static inline struct binder_thread *binder_new_thread(pid_t pid)
{	
	struct binder_thread *thread;
	int i;

	thread = kmalloc(sizeof(*thread), GFP_KERNEL);
	if (!thread)
		return NULL;

	thread->pid = pid;
	thread->queue = create_msg_queue(0, free_transaction);
	if (!thread->queue) {
		kfree(thread);
		return NULL;
	}

	thread->num_pending = 0;
	for (i = 0; i < sizeof(thread->pending_transactions) / sizeof(thread->pending_transactions[0]); i++)
		INIT_LIST_HEAD(&thread->pending_transactions[i]);

	return thread;
}

static struct binder_thread *binder_get_thread(struct binder_proc *proc)
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

	spin_lock(&proc->lock);
	rb_link_node(&thread->rb_node, parent, p);
	rb_insert_color(&thread->rb_node, &proc->thread_tree);
	spin_unlock(&proc->lock);

	return thread;
}

static inline int cmd_read_write(struct binder_proc *proc, struct binder_thread *thread, struct binder_write_read *bwr)
{
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

	thread = binder_get_thread(proc);
	if (unlikely(!thread))
		return -ENOMEM;

	switch (cmd) {
		case BINDER_WRITE_READ: {
			struct binder_write_read bwr;

			if (size != sizeof(bwr))
				return -EINVAL;
			if (copy_from_user(&bwr, ubuf, sizeof(bwr)))
				return -EFAULT;

			return cmd_read_write(proc, thread, &bwr);
		}

		case BINDER_THREAD_EXIT:
			return cmd_thread_exit(proc, thread);

		case BINDER_SET_MAX_THREADS: {
			int max_threads;

			if (size != sizeof(int))
				return -EINVAL;
			if (get_user(&max_threads, ubuf))
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
