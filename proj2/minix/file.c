/*
 *  linux/fs/minix/file.c
 *
 *  Copyright (C) 1991, 1992 Linus Torvalds
 *
 *  minix regular file handling primitives
 */

#include "minix.h"
#include "linux/uio.h"
#include "linux/swap.h"

/**
 * do_generic_file_read - generic file read routine
 * @filp:    the file to read
 * @ppos:    current file position
 * @iter:    data destination
 * @written:    already copied
 *
 * This is a generic file read routine, and uses the
 * mapping->a_ops->readpage() function for the actual low-level stuff.
 *
 * This is really ugly. But the goto's actually try to clarify some
 * of the logic when it comes to error handling etc.
 */
static ssize_t do_generic_file_read(struct file *filp, loff_t *ppos,
                                    struct iov_iter *iter, ssize_t written)
{
    struct address_space *mapping = filp->f_mapping;
    struct inode *inode = mapping->host;
    struct file_ra_state *ra = &filp->f_ra;
    pgoff_t index;
    pgoff_t last_index;
    pgoff_t prev_index;
    unsigned long offset;      /* offset into pagecache page */
    unsigned int prev_offset;
    int error = 0;

    if (unlikely(*ppos >= inode->i_sb->s_maxbytes))
        return 0;
    iov_iter_truncate(iter, inode->i_sb->s_maxbytes);

    index = *ppos >> PAGE_SHIFT;
    prev_index = ra->prev_pos >> PAGE_SHIFT;
    prev_offset = ra->prev_pos & (PAGE_SIZE-1);
    last_index = (*ppos + iter->count + PAGE_SIZE-1) >> PAGE_SHIFT;
    offset = *ppos & ~PAGE_MASK;

    for (;;) {
        struct page *page;
        pgoff_t end_index;
        loff_t isize;
        unsigned long nr, ret;

        cond_resched();
    find_page:
        if (fatal_signal_pending(current)) {
            error = -EINTR;
            goto out;
        }

        page = find_get_page(mapping, index);
        if (!page) {
            page_cache_sync_readahead(mapping,
                                      ra, filp,
                                      index, last_index - index);
            page = find_get_page(mapping, index);
            if (unlikely(page == NULL))
                goto no_cached_page;
        }
        if (PageReadahead(page)) {
            page_cache_async_readahead(mapping,
                                       ra, filp, page,
                                       index, last_index - index);
        }
        if (!PageUptodate(page)) {
            /*
             * See comment in do_read_cache_page on why
             * wait_on_page_locked is used to avoid unnecessarily
             * serialisations and why it's safe.
             */
            error = wait_on_page_locked_killable(page);
            if (unlikely(error))
                goto readpage_error;
            if (PageUptodate(page))
                goto page_ok;

            if (inode->i_blkbits == PAGE_SHIFT ||
                !mapping->a_ops->is_partially_uptodate)
                goto page_not_up_to_date;
            /* pipes can't handle partially uptodate pages */
            if (unlikely(iter->type & ITER_PIPE))
                goto page_not_up_to_date;
            if (!trylock_page(page))
                goto page_not_up_to_date;
            /* Did it get truncated before we got the lock? */
            if (!page->mapping)
                goto page_not_up_to_date_locked;
            if (!mapping->a_ops->is_partially_uptodate(page,
                                                       offset, iter->count))
                goto page_not_up_to_date_locked;
            unlock_page(page);
        }
    page_ok:
        /*
         * i_size must be checked after we know the page is Uptodate.
         *
         * Checking i_size after the check allows us to calculate
         * the correct value for "nr", which means the zero-filled
         * part of the page is not copied back to userspace (unless
         * another truncate extends the file - this is desired though).
         */

        isize = i_size_read(inode);
        end_index = (isize - 1) >> PAGE_SHIFT;
        if (unlikely(!isize || index > end_index)) {
            put_page(page);
            goto out;
        }

        /* nr is the maximum number of bytes to copy from this page */
        nr = PAGE_SIZE;
        if (index == end_index) {
            nr = ((isize - 1) & ~PAGE_MASK) + 1;
            if (nr <= offset) {
                put_page(page);
                goto out;
            }
        }
        nr = nr - offset;

        /* If users can be writing to this page using arbitrary
         * virtual addresses, take care about potential aliasing
         * before reading the page on the kernel side.
         */
        if (mapping_writably_mapped(mapping))
            flush_dcache_page(page);

        /*
         * When a sequential read accesses a page several times,
         * only mark it as accessed the first time.
         */
        if (prev_index != index || offset != prev_offset)
            mark_page_accessed(page);
        prev_index = index;

        /*
         * Ok, we have the page, and it's up-to-date, so
         * now we can copy it to user space...
         */

        ret = copy_page_to_iter(page, offset, nr, iter);
        offset += ret;
        index += offset >> PAGE_SHIFT;
        offset &= ~PAGE_MASK;
        prev_offset = offset;

        put_page(page);
        written += ret;
        if (!iov_iter_count(iter))
            goto out;
        if (ret < nr) {
            error = -EFAULT;
            goto out;
        }
        continue;

    page_not_up_to_date:
        /* Get exclusive access to the page ... */
        error = lock_page_killable(page);
        if (unlikely(error))
            goto readpage_error;

    page_not_up_to_date_locked:
        /* Did it get truncated before we got the lock? */
        if (!page->mapping) {
            unlock_page(page);
            put_page(page);
            continue;
        }

        /* Did somebody else fill it already? */
        if (PageUptodate(page)) {
            unlock_page(page);
            goto page_ok;
        }

    readpage:
        /*
         * A previous I/O error may have been due to temporary
         * failures, eg. multipath errors.
         * PG_error will be set again if readpage fails.
         */
        ClearPageError(page);
        /* Start the actual read. The read will unlock the page. */
        error = mapping->a_ops->readpage(filp, page);

        if (unlikely(error)) {
            if (error == AOP_TRUNCATED_PAGE) {
                put_page(page);
                error = 0;
                goto find_page;
            }
            goto readpage_error;
        }

        if (!PageUptodate(page)) {
            error = lock_page_killable(page);
            if (unlikely(error))
                goto readpage_error;
            if (!PageUptodate(page)) {
                if (page->mapping == NULL) {
                    /*
                     * invalidate_mapping_pages got it
                     */
                    unlock_page(page);
                    put_page(page);
                    goto find_page;
                }
                unlock_page(page);
                ra->ra_pages /= 4;
                error = -EIO;
                goto readpage_error;
            }
            unlock_page(page);
        }

        goto page_ok;

    readpage_error:
        /* UHHUH! A synchronous read error occurred. Report it */
        put_page(page);
        goto out;

    no_cached_page:
        /*
         * Ok, it wasn't cached, so we need to create a new
         * page..
         */
        page = page_cache_alloc_cold(mapping);
        if (!page) {
            error = -ENOMEM;
            goto out;
        }
        error = add_to_page_cache_lru(page, mapping, index,
                                      mapping_gfp_constraint(mapping, GFP_KERNEL));
        if (error) {
            put_page(page);
            if (error == -EEXIST) {
                error = 0;
                goto find_page;
            }
            goto out;
        }
        goto readpage;
    }

out:
    ra->prev_pos = prev_index;
    ra->prev_pos <<= PAGE_SHIFT;
    ra->prev_pos |= prev_offset;

    *ppos = ((loff_t)index << PAGE_SHIFT) + offset;
    file_accessed(filp);
    return written ? written : error;
}


/**
 * generic_file_write_iter - write data to a file
 * @iocb:    IO state structure
 * @from:    iov_iter with data to write
 *
 * This is a wrapper around __generic_file_write_iter() to be used by most
 * filesystems. It takes care of syncing the file in case of O_SYNC file
 * and acquires i_mutex as needed.
 */
ssize_t crypto_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
    struct file *file = iocb->ki_filp;
    struct inode *inode = file->f_mapping->host;
    ssize_t ret;
    printk(KERN_INFO "Crypto: Customised print at %s\n", __FUNCTION__);

    inode_lock(inode);
    ret = generic_write_checks(iocb, from);
    if (ret > 0)
        ret = __generic_file_write_iter(iocb, from);
    inode_unlock(inode);

    if (ret > 0)
        ret = generic_write_sync(iocb, ret);
    return ret;
}


/**
 * generic_file_read_iter - generic filesystem read routine
 * @iocb:    kernel I/O control block
 * @iter:    destination for the data read
 *
 * This is the "read_iter()" routine for all filesystems
 * that can use the page cache directly.
 */
ssize_t crypto_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
    struct file *file = iocb->ki_filp;
    ssize_t retval = 0;
    size_t count = iter->count;

    printk(KERN_INFO "Crypto: Customised print at %s\n", __FUNCTION__);
    if (!count)
        goto out; /* skip atime */

    if (iocb->ki_flags & IOCB_DIRECT) {
        struct address_space *mapping = file->f_mapping;
        struct inode *inode = mapping->host;
        struct iov_iter data = *iter;
        loff_t size;

        size = i_size_read(inode);
        retval = filemap_write_and_wait_range(mapping, iocb->ki_pos,
                                              iocb->ki_pos + count - 1);
        if (retval < 0)
            goto out;

        file_accessed(file);

        retval = mapping->a_ops->direct_IO(iocb, &data);
        if (retval >= 0) {
            iocb->ki_pos += retval;
            iov_iter_advance(iter, retval);
        }

        /*
         * Btrfs can have a short DIO read if we encounter
         * compressed extents, so if there was an error, or if
         * we've already read everything we wanted to, or if
         * there was a short read because we hit EOF, go ahead
         * and return.  Otherwise fallthrough to buffered io for
         * the rest of the read.  Buffered reads will not work for
         * DAX files, so don't bother trying.
         */
        if (retval < 0 || !iter->count || iocb->ki_pos >= size ||
            IS_DAX(inode))
            goto out;
    }

    retval = do_generic_file_read(file, &iocb->ki_pos, iter, retval);
out:
    return retval;
}

/*
 * We have mostly NULLs here: the current defaults are OK for
 * the minix filesystem.
 */
const struct file_operations minix_file_operations = {
	.llseek		= generic_file_llseek,
	.read_iter	= crypto_file_read_iter, // Customised decyphed file read
	.write_iter	= crypto_file_write_iter, // Customised cyphed file write
	.mmap		= generic_file_mmap,
	.fsync		= generic_file_fsync,
	.splice_read	= generic_file_splice_read,
};

static int minix_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	int error;

	error = setattr_prepare(dentry, attr);
	if (error)
		return error;

	if ((attr->ia_valid & ATTR_SIZE) &&
	    attr->ia_size != i_size_read(inode)) {
		error = inode_newsize_ok(inode, attr->ia_size);
		if (error)
			return error;

		truncate_setsize(inode, attr->ia_size);
		minix_truncate(inode);
	}

	setattr_copy(inode, attr);
	mark_inode_dirty(inode);
	return 0;
}

const struct inode_operations minix_file_inode_operations = {
	.setattr	= minix_setattr,
	.getattr	= minix_getattr,
};
