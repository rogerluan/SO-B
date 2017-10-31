/*
 *  linux/fs/minix/file.c
 *
 *  Copyright (C) 1991, 1992 Linus Torvalds
 *
 *  minix regular file handling primitives
 */

#include "minix.h"
#include "linux/uio.h"
#include <linux/fs.h>

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
