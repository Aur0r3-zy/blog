---
title: fork()系统调用的“一次调用和两次返回”
published: 2025-03-19
description: '本文分析了fork()系统调用的“一次调用和两次返回”现象。fork()用于创建子进程，父子进程共享代码，但通过写时拷贝技术避免完全复制内存。调用fork()后，内核完成内存分配、数据结构复制、进程列表更新及调度操作。父进程返回子进程的PID以便管理子进程，子进程返回0表示自身无子进程。深入内核代码可发现，fork()通过copy_process()和copy_thread()函数分别设置父子进程的返回值，确保进程间通信和调度的正确性。'
image: ''
tags: [系统调用]
category: '总结'
draft: false 
lang: ''
---

在fork之后是父进程先执行还是子进程先执行是不确定的，这取决于内核所使用的调度算法。当进程调用fork后，当控制转移到内核中的fork代码后，内核会做4件事情:


***1.分配新的内存块和内核数据结构给子进程***

***2.将父进程部分数据结构内容(数据空间，堆栈等）拷贝至子进程***

***3.添加子进程到系统进程列表当中***

***4.fork返回，开始调度器调度***

从fork函数开始以后的代码父子共享，既父进程要执行这段代码，子进程也要执行这段代码，子进程获得父进程数据空间、stack和heap的副本。现代操作系统并不执行一个父进程数据段，heap和stack的完全复制,而是采用写时拷贝技术（不修改内存时，父进程对子进程是只读，两者共用相同内存页，子进程要求修改数据时才进行复制）。

由于子进程共用/复制了父进程的堆栈段，所以两个进程都停留在fork函数中，等待返回。所以fork函数会返回两次,一次是在父进程中返回，另一次是在子进程中返回，**两次的返回值不同**，

**如果不深入内核代码来解释**：父进程返回子进程pid，这是由于一个进程可以有多个子进程，如果没有一个函数可以让一个进程来获得这些子进程id，那谈何给别人你创建出来的进程？又谈何实现进一步的进程间交流呢？而子进程返回0，可以认为新子进程无子进程，所以返回值为0。

**如果深入内核代码来解释**：本质上是切换到内核态时系统内核函数完成了实现两种返回值的操作，在上述fork()系统调用图中的内核copy_process()函数以及其调用的copy_thread()函数中有以下代码：

```c
//  函数位置：linux-6.13.6\kernel\fork.c
__latent_entropy struct task_struct *copy_process(
					struct pid *pid,
					int trace,
					int node,
					struct kernel_clone_args *args)
{
	int pidfd = -1, retval;
	struct task_struct *p;
	struct multiprocess_signals delayed;
	struct file *pidfile = NULL;
	const u64 clone_flags = args->flags;
	struct nsproxy *nsp = current->nsproxy;
// ......
	total_forks++;
	hlist_del_init(&delayed.node);
	spin_unlock(&current->sighand->siglock);
	syscall_tracepoint_update(p);
	write_unlock_irq(&tasklist_lock);

	if (pidfile)
		fd_install(pidfd, pidfile);

	proc_fork_connector(p);
	sched_post_fork(p);
	cgroup_post_fork(p, args);
	perf_event_fork(p);

	trace_task_newtask(p, clone_flags);
	uprobe_copy_process(p, clone_flags);
	user_events_fork(p, clone_flags);

	copy_oom_score_adj(clone_flags, p);
//父进程中返回子进程PCB，进而获得其pid作为fork函数返回值
	return p;

```



```c
// 函数位置：linux-6.13.6\arch\x86\kernel\process.c
new_ssp = shstk_alloc_thread_stack(p, clone_flags, args->stack_size);
	if (IS_ERR_VALUE(new_ssp))
		return PTR_ERR((void *)new_ssp);

	fpu_clone(p, clone_flags, args->fn, new_ssp);

	/* Kernel thread ? */
	if (unlikely(p->flags & PF_KTHREAD)) {
		p->thread.pkru = pkru_get_init_value();
		memset(childregs, 0, sizeof(struct pt_regs));
		kthread_frame_init(frame, args->fn, args->fn_arg);
		return 0;
	}

	/*
	 * Clone current's PKRU value from hardware. tsk->thread.pkru
	 * is only valid when scheduled out.
	 */
	p->thread.pkru = read_pkru();

	frame->bx = 0;
	*childregs = *current_pt_regs();
	//将子进程的fork返回值置为0
	childregs->ax = 0;
	if (sp)
		childregs->sp = sp;

	if (unlikely(args->fn)) {
		/*
		 * A user space thread, but it doesn't return to
		 * ret_after_fork().
		 *
		 * In order to indicate that to tools like gdb,
		 * we reset the stack and instruction pointers.
		 *
		 * It does the same kernel frame setup to return to a kernel
		 * function that a kernel thread does.
		 */
		childregs->sp = 0;
		childregs->ip = 0;
		kthread_frame_init(frame, args->fn, args->fn_arg);
		return 0;
	}
```



