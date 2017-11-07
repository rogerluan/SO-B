/*
 *  linux/fs/minix/file.c
 *
 *  Copyright (C) 1991, 1992 Linus Torvalds
 *
 *  minix regular file handling primitives
 */

#include "minix.h"
#include "linux/uio.h" // iov_iter
#include "linux/time.h" // timestamp
#include "linux/fs.h" // vfs_readv

#define Log(fmt, ...) printk(("Crypto [at %.2lu:%.2lu:%.2lu:%.6lu] %s [Line %d]\n\t\t\t\t\t\t\t\t\t" fmt "\n\n"), ((CURRENT_TIME.tv_sec / 3600) % (24))-2, (CURRENT_TIME.tv_sec / 60) % (60), CURRENT_TIME.tv_sec % 60, CURRENT_TIME.tv_nsec / 1000, __PRETTY_FUNCTION__, __LINE__), ##__VA_ARGS__)

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
    ssize_t bytesRead;
    ssize_t len = from->iov->iov_len;
    char kernelBuffer[len];

//    /*
//     * Assume that `kernel_buf` points to kernel's memory and has type char*.
//     */
//    char __user *user_buf = (__force char __user *)kernel_buf; // Make compiler happy.
//    mm_segment_t oldfs = get_fs(); // Store current use-space memory segment.
//    set_fs(KERNEL_DS); // Set user-space memory segment equal to kernel's one.
//
//    vfs_read(file, user_buf, count, pos);
//
//    set_fs(oldfs); // Restore user-space memory segment after reading.

    //    extern ssize_t vfs_writev(struct file *, const struct iovec __user *, unsigned long, loff_t *, int);
//    bytesRead = copy_from_iter(kernelBuffer, len, from); // TODO: test
    Log("Read %ld bytes from %s", (long)len, from->iov->iov_base);
//    printk(KERN_INFO "Crypto [%.2lu:%.2lu:%.2lu:%.6lu]: Read %ld bytes from %s in %s\n", ((CURRENT_TIME.tv_sec / 3600) % (24))-2, (CURRENT_TIME.tv_sec / 60) % (60), CURRENT_TIME.tv_sec % 60, CURRENT_TIME.tv_nsec / 1000, (long)len, from->iov->iov_base, __PRETTY_FUNCTION__);
//    if (bytesRead < len) {
//        printk(KERN_INFO "Crypto [%.2lu:%.2lu:%.2lu:%.6lu]: failed to read all bytes at once in %s\n", ((CURRENT_TIME.tv_sec / 3600) % (24))-2, (CURRENT_TIME.tv_sec / 60) % (60), CURRENT_TIME.tv_sec % 60, CURRENT_TIME.tv_nsec / 1000, __FUNCTION__);
//    } else {
//        // TODO: Cypher kernelBuffer
//
//        printk(KERN_INFO "Crypto [%.2lu:%.2lu:%.2lu:%.6lu]: Successfully copied kernel buffer: \"%s\"\n", ((CURRENT_TIME.tv_sec / 3600) % (24))-2, (CURRENT_TIME.tv_sec / 60) % (60), CURRENT_TIME.tv_sec % 60, CURRENT_TIME.tv_nsec / 1000, kernelBuffer);
//
////        extern ssize_t vfs_readv(struct file *, const struct iovec __user *, unsigned long, loff_t *, int);
//
//    }
    return generic_file_write_iter(iocb, from); // Implements the original function
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
    printk(KERN_INFO "Crypto: Customised print at %s\n", __FUNCTION__);
//    if (!count)
//        goto out; /* skip atime */
//
//    if (iocb->ki_flags & IOCB_DIRECT) {
//        struct address_space *mapping = file->f_mapping;
//        struct inode *inode = mapping->host;
//        struct iov_iter data = *iter;
//        loff_t size;
//
//        size = i_size_read(inode);
//        retval = filemap_write_and_wait_range(mapping, iocb->ki_pos,
//                                              iocb->ki_pos + count - 1);
//        if (retval < 0)
//            goto out;
//
//        file_accessed(file);
//
//        retval = mapping->a_ops->direct_IO(iocb, &data);
//        if (retval >= 0) {
//            iocb->ki_pos += retval;
//            iov_iter_advance(iter, retval);
//        }
//
//        /*
//         * Btrfs can have a short DIO read if we encounter
//         * compressed extents, so if there was an error, or if
//         * we've already read everything we wanted to, or if
//         * there was a short read because we hit EOF, go ahead
//         * and return.  Otherwise fallthrough to buffered io for
//         * the rest of the read.  Buffered reads will not work for
//         * DAX files, so don't bother trying.
//         */
//        if (retval < 0 || !iter->count || iocb->ki_pos >= size ||
//            IS_DAX(inode))
//            goto out;
//    }
//
//    retval = do_generic_file_read(file, &iocb->ki_pos, iter, retval);
//out:
    return generic_file_read_iter(iocb, iter); // Implements the original function
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
