/*
 *  linux/fs/minix/file.c
 *
 *  Copyright (C) 1991, 1992 Linus Torvalds
 *
 *  minix regular file handling primitives
 */

#include "minix.h"
#include "linux/uio.h" // iov_iter
#include "linux/time.h"           // Timestamp
#include <linux/fs.h>             // Header for the Linux file system support
#include <asm/uaccess.h>          // Required for the copy to user function
#include <linux/string.h>         // String manipulation
#include <linux/crypto.h>         // crypto_async_request definition
#include <linux/scatterlist.h>    // scatterlist struct definition
#include <crypto/skcipher.h>      // crypto_skcipher_encrypt definition


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat"
#define Log(fmt, ...) printk(("Crypto [at %.2lu:%.2lu:%.2lu:%.6lu] %s [Line %d]\n\t\t\t\t   " fmt "\n\n"), ((CURRENT_TIME.tv_sec / 3600) % (24))-2, (CURRENT_TIME.tv_sec / 60) % (60), CURRENT_TIME.tv_sec % 60, CURRENT_TIME.tv_nsec / 1000, __PRETTY_FUNCTION__, __LINE__, ##__VA_ARGS__)
#pragma GCC pop


#define BUFFER_SIZE 2048
#define SENTENCE_BLOCK_SIZE 16

//// Parameters
static char *key = "alpineqwertyuiop";
//module_param(key, charp, 0); // Compatible with kernel 4+
//MODULE_PARM_DESC(key, "This is the symetric key used to cypher and decypher de data.");

static char message[BUFFER_SIZE] = {0};   ///< Memory for the string that is passed from userspace

//
static int bgmr_cipher(char *sentence, int encrypt);

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
    ssize_t len = from->iov->iov_len;
    char kernelBuffer[len];
    int errorCount = copy_from_user(kernelBuffer, from->iov->iov_base, len);
    kernelBuffer[len]='\0';
    if (errorCount != 0) {
        printk(KERN_INFO "CryptoDevice: Failed to receive %d characters from the user\n", errorCount);
        return -EFAULT;              // Failed -- return a bad address message (i.e. -14)
    }


    Log("kernel buffer: %s", kernelBuffer);
    bgmr_cipher(kernelBuffer, 1);


//    strncpy(sentence, kernelBuffer+2, sizeof(sentence));
//    printk(KERN_INFO "SENTENCE COPIED: %s\n", sentence);

    // Cipher
//    printk(KERN_INFO "CryptoDevice: Cypher\n");
//    bgmr_cipher(sentence, 1);
    Log("Writing and ciphering %ld bytes: \"%s\"", (long)len, from->iov->iov_base);
    return len;

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




// MARK: Crypto Methods

struct tcrypt_result {
    struct completion completion;
    int err;
};

/* tie all data structures together */
struct skcipher_def {
    struct scatterlist sg;
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct tcrypt_result result;
};

/* Callback function */
static void test_skcipher_cb(struct crypto_async_request *req, int error) {
    struct tcrypt_result *result = req->data;

    if (error == -EINPROGRESS) {
        pr_info("Encryption is still under progress. Returning... \n");
        return;
    }
    result->err = error;
    pr_info("Encryption finished successfully\n");
    complete(&result->completion);
}

/* Perform cipher operation */
static unsigned int test_skcipher_encdec(struct skcipher_def *sk, int enc) {
    int rc = 0;

    if (enc) {
        pr_info("Encrypt\n");
        rc = crypto_skcipher_encrypt(sk->req);
    } else {
        pr_info("Decrypt\n");
        rc = crypto_skcipher_decrypt(sk->req);
    }

    switch (rc) {
        case 0: break;
        case -EINPROGRESS:
        case -EBUSY:
            rc = wait_for_completion_interruptible(&sk->result.completion);
            if (!rc && !sk->result.err) {
                reinit_completion(&sk->result.completion);
                break;
            }
        default:
            pr_info("skcipher encrypt returned with %d result %d\n", rc, sk->result.err);
            break;
    }
    init_completion(&sk->result.completion);

    return rc;
}

/* Initialize and trigger cipher operation */
static int bgmr_cipher(char *sentence, int encrypt) {
    struct skcipher_def sk;
    struct crypto_skcipher *skcipher = NULL;
    struct skcipher_request *req = NULL;

    char blockSizeSentence[SENTENCE_BLOCK_SIZE] = {0};
    char tempDecryptedMessage[BUFFER_SIZE] = {0};

    int index = 0;
    int ret = -EFAULT;
    int sentenceLength = strlen(sentence);
    int isMultipleOf16 = (sentenceLength % 16 == 0);
    int blockCount = isMultipleOf16 ? sentenceLength/16 : (int)sentenceLength/16 + 1; // Sentence length is always >= 0
    //strncpy(blockSizeSentence, sentence, strlen(sentence));
    pr_info("Sentece in CRYPT %s\n", blockSizeSentence);

    skcipher = crypto_alloc_skcipher("ecb(aes)", 0, 0);
    if (IS_ERR(skcipher)) {
        pr_info("could not allocate skcipher handle\n");
        return PTR_ERR(skcipher);
    }

    req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    if (!req) {
        pr_info("could not allocate skcipher request\n");
        ret = -ENOMEM;
        goto out;
    }

    skcipher_request_set_callback(req, 0, test_skcipher_cb, &message);

    /* AES 256 with random key */
    if (crypto_skcipher_setkey(skcipher, key, strlen(key))) {
        pr_info("key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }

    sk.tfm = skcipher;
    sk.req = req;
    pr_info("Before Multiple os 16: %d\n", ((blockCount-1)*16));
    if (!isMultipleOf16) {
        int rest = sentenceLength % 16;
        strncpy(blockSizeSentence, sentence + ((blockCount-1)*16), rest);
        //blockSizeSentence[SENTENCE_BLOCK_SIZE]='\0';
        pr_info("REST: %d\n", rest);
    }

    for (index = 0; index < blockCount; ++index) {

        if(index == blockCount-1 && !isMultipleOf16) {
            sg_init_one(&sk.sg, &blockSizeSentence[0], 16);
        }
        else{
            sg_init_one(&sk.sg, &sentence[index*16], 16);
        }
        skcipher_request_set_crypt(req, &sk.sg, &sk.sg, 16, NULL);
        init_completion(&sk.result.completion);

        /* encrypt data */
        ret = test_skcipher_encdec(&sk, encrypt);
        if (ret) { goto out; }

        sg_copy_to_buffer(&sk.sg, 1, &message[index*16], 16);

        // Decrypt data to show on kernlog
        ret = test_skcipher_encdec(&sk, !encrypt);
        if (ret) { goto out; }

        sg_copy_to_buffer(&sk.sg, 1, &tempDecryptedMessage[index*16], 16);

    }

    Log("Encryption triggered successfully. Encrypted: \n");
    int i;
    for (i = 0; i < strlen(message); i++){
        printf("%02X",(unsigned char)message[i]);
    }
    Log("Decrypted: %s\n", tempDecryptedMessage);

out:
    if (skcipher) {
        crypto_free_skcipher(skcipher);
    }
    if (req) {
        skcipher_request_free(req);
    }
    return ret;
}


