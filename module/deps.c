#include <linux/sched.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/atomic.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include "deps.h"

static struct sighand_struct *(*__lock_task_sighand_ptr)(struct task_struct *, unsigned long *) = __LOCK_TASK_SIGHAND;
static struct files_struct *(*get_files_struct_ptr)(struct task_struct *) = GET_FILES_STRUCT;
static void (*put_files_struct_ptr)(struct files_struct *) = PUT_FILES_STRUCT;
static void (*unmap_kernel_range_ptr)(unsigned long, unsigned long) = UNMAP_KERNEL_RANGE;
static int (*expand_files_ptr)(struct files_struct *, int) = EXPAND_FILES;
static unsigned long (*zap_page_range_ptr)(struct vm_area_struct *, unsigned long, unsigned long, struct zap_details *) = ZAP_PAGE_RANGE;
static struct vm_struct *(*get_vm_area_ptr)(unsigned long, unsigned long) = GET_VM_AREA;
static int (*can_nice_ptr)(const struct task_struct *, const int) = CAN_NICE;


struct sighand_struct *__lock_task_sighand(struct task_struct *tsk, unsigned long *flags)
{
	return __lock_task_sighand_ptr(tsk, flags);
}

struct files_struct *get_files_struct(struct task_struct *task)
{
	return get_files_struct_ptr(task);
}

void put_files_struct(struct files_struct *files)
{
	put_files_struct_ptr(files);
}

void unmap_kernel_range(unsigned long addr, unsigned long size)
{
	unmap_kernel_range_ptr(addr, size);
}

int expand_files(struct files_struct *files, int nr)
{
	return expand_files_ptr(files, nr);
}

unsigned long zap_page_range(struct vm_area_struct *vma, unsigned long address, unsigned long size, struct zap_details *details)
{
	return zap_page_range_ptr(vma, address, size, details);
}

struct vm_struct *get_vm_area(unsigned long size, unsigned long flags)
{
	return get_vm_area_ptr(size, flags);
}

int can_nice(const struct task_struct *p, const int nice)
{
	return can_nice_ptr(p, nice);
}
