/*
 * Flexible Per-CPU Reader-Writer Locks
 * (with relaxed locking rules and reduced deadlock-possibilities)
 *
 * Copyright (C) IBM Corporation, 2012-2013
 * Author: Srivatsa S. Bhat <srivatsa.bhat@linux.vnet.ibm.com>
 *
 * With lots of invaluable suggestions from:
 *	   Oleg Nesterov <oleg@redhat.com>
 *	   Tejun Heo <tj@kernel.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/spinlock.h>
#include <linux/percpu.h>
#include <linux/lockdep.h>
#include <linux/percpu-rwlock.h>
#include <linux/errno.h>

#include <asm/processor.h>


#define reader_yet_to_switch(pcpu_rwlock, cpu)				    \
	(ACCESS_ONCE(per_cpu_ptr((pcpu_rwlock)->rw_state, cpu)->reader_refcnt))

#define reader_percpu_nesting_depth(pcpu_rwlock)		  \
	(__this_cpu_read((pcpu_rwlock)->rw_state->reader_refcnt))

#define reader_uses_percpu_refcnt(pcpu_rwlock)				\
				reader_percpu_nesting_depth(pcpu_rwlock)

#define reader_nested_percpu(pcpu_rwlock)				\
			(reader_percpu_nesting_depth(pcpu_rwlock) > 1)

#define writer_active(pcpu_rwlock)					\
	(__this_cpu_read((pcpu_rwlock)->rw_state->writer_signal))


int __percpu_init_rwlock(struct percpu_rwlock *pcpu_rwlock,
			 const char *name, struct lock_class_key *rwlock_key)
{
	pcpu_rwlock->rw_state = alloc_percpu(struct rw_state);
	if (unlikely(!pcpu_rwlock->rw_state))
		return -ENOMEM;

	/* ->global_rwlock represents the whole percpu_rwlock for lockdep */
#ifdef CONFIG_DEBUG_SPINLOCK
	__rwlock_init(&pcpu_rwlock->global_rwlock, name, rwlock_key);
#else
	pcpu_rwlock->global_rwlock =
			__RW_LOCK_UNLOCKED(&pcpu_rwlock->global_rwlock);
#endif
	return 0;
}

void percpu_free_rwlock(struct percpu_rwlock *pcpu_rwlock)
{
	free_percpu(pcpu_rwlock->rw_state);

	/* Catch use-after-free bugs */
	pcpu_rwlock->rw_state = NULL;
}

void percpu_read_lock(struct percpu_rwlock *pcpu_rwlock)
{
	preempt_disable();

	/*
	 * Let the writer know that a reader is active, even before we choose
	 * our reader-side synchronization scheme.
	 */
	this_cpu_inc(pcpu_rwlock->rw_state->reader_refcnt);

	/*
	 * If we are already using per-cpu refcounts, it is not safe to switch
	 * the synchronization scheme. So continue using the refcounts.
	 */
	if (reader_nested_percpu(pcpu_rwlock))
		return;

	/*
	 * The write to 'reader_refcnt' must be visible before we read
	 * 'writer_signal'.
	 */
	smp_mb();

	if (likely(!writer_active(pcpu_rwlock))) {
		goto out;
	} else {
		/* Writer is active, so switch to global rwlock. */
		read_lock(&pcpu_rwlock->global_rwlock);

		/*
		 * We might have raced with a writer going inactive before we
		 * took the read-lock. So re-evaluate whether we still need to
		 * hold the rwlock or if we can switch back to per-cpu
		 * refcounts. (This also helps avoid heterogeneous nesting of
		 * readers).
		 */
		if (writer_active(pcpu_rwlock)) {
			/*
			 * The above writer_active() check can get reordered
			 * with this_cpu_dec() below, but this is OK, because
			 * holding the rwlock is conservative.
			 */
			this_cpu_dec(pcpu_rwlock->rw_state->reader_refcnt);
		} else {
			read_unlock(&pcpu_rwlock->global_rwlock);
		}
	}

out:
	/* Prevent reordering of any subsequent reads/writes */
	smp_mb();
}

void percpu_read_unlock(struct percpu_rwlock *pcpu_rwlock)
{
	/*
	 * We never allow heterogeneous nesting of readers. So it is trivial
	 * to find out the kind of reader we are, and undo the operation
	 * done by our corresponding percpu_read_lock().
	 */

	/* Try to fast-path: a nested percpu reader is the simplest case */
	if (reader_nested_percpu(pcpu_rwlock)) {
		this_cpu_dec(pcpu_rwlock->rw_state->reader_refcnt);
		preempt_enable();
		return;
	}

	/*
	 * Now we are left with only 2 options: a non-nested percpu reader,
	 * or a reader holding rwlock
	 */
	if (reader_uses_percpu_refcnt(pcpu_rwlock)) {
		/*
		 * Complete the critical section before decrementing the
		 * refcnt. We can optimize this away if we are a nested
		 * reader (the case above).
		 */
		smp_mb();
		this_cpu_dec(pcpu_rwlock->rw_state->reader_refcnt);
	} else {
		read_unlock(&pcpu_rwlock->global_rwlock);
	}

	preempt_enable();
}

void percpu_write_lock(struct percpu_rwlock *pcpu_rwlock)
{
	unsigned int cpu;

	/*
	 * Tell all readers that a writer is becoming active, so that they
	 * start switching over to the global rwlock.
	 */
	for_each_possible_cpu(cpu)
		per_cpu_ptr(pcpu_rwlock->rw_state, cpu)->writer_signal = true;

	smp_mb();

	/*
	 * Wait for every reader to see the writer's signal and switch from
	 * percpu refcounts to global rwlock.
	 *
	 * If a reader is still using percpu refcounts, wait for him to switch.
	 * Else, we can safely go ahead, because either the reader has already
	 * switched over, or the next reader that comes along on that CPU will
	 * notice the writer's signal and will switch over to the rwlock.
	 */

	for_each_possible_cpu(cpu) {
		while (reader_yet_to_switch(pcpu_rwlock, cpu))
			cpu_relax();
	}

	smp_mb(); /* Complete the wait-for-readers, before taking the lock */
	write_lock(&pcpu_rwlock->global_rwlock);
}

void percpu_write_unlock(struct percpu_rwlock *pcpu_rwlock)
{
	unsigned int cpu;

	/* Complete the critical section before clearing ->writer_signal */
	smp_mb();

	/*
	 * Inform all readers that we are done, so that they can switch back
	 * to their per-cpu refcounts. (We don't need to wait for them to
	 * see it).
	 */
	for_each_possible_cpu(cpu)
		per_cpu_ptr(pcpu_rwlock->rw_state, cpu)->writer_signal = false;

	write_unlock(&pcpu_rwlock->global_rwlock);
}

