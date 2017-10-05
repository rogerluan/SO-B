/**
 * @file crypto.c
 * @author BRUNO AUGUSTO PEDROSO       12662136
           GIULIANA SALGADO ALEPROTI   12120457
           MATHEUS DE PAULA NICOLAU    12085957
           ROGER OBA                   12048534
 * @date September 26th, 2017
 * @version 1.0
 * @brief A character device that cypher, decypher and hash strings.
 */

#include <linux/init.h>           // Macros used to mark up functions e.g. __init __exit
#include <linux/module.h>         // Core header for loading LKMs into the kernel
#include <linux/device.h>         // Header to support the kernel Driver Model
#include <linux/kernel.h>         // Contains types, macros, functions for the kernel
#include <linux/fs.h>             // Header for the Linux file system support
#include <asm/uaccess.h>          // Required for the copy to user function
#include <linux/string.h>         // String manipulation
#include <linux/crypto.h>         // crypto_async_request definition
#include <linux/scatterlist.h>    // scatterlist struct definition
#include <crypto/skcipher.h>      // crypto_skcipher_encrypt definition
#include <linux/random.h>         // random function declarations

#define DEVICE_NAME "cryptochar"    ///< The device will appear at /dev/cryptochar using this value
#define CLASS_NAME  "crypto"        ///< The device class -- this is a character device driver
#define BUFFER_SIZE 2048

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bruno Augusto Pedroso\t\t12662136\nGiuliana Salgado Aleproti\t12120457\nMatheus de Paula Nicolau\t12085957\nRoger Oba\t\t\t\t\t12048534");
MODULE_DESCRIPTION("A character device that cypher, decypher and hash strings.");
MODULE_VERSION("1.0");

// Parameters
static char *key = "alpine";
//module_param(key, charp, 0000); // Compatible with kernel 3.2.36
module_param(key, charp, 0); // Compatible with kernel 4+
MODULE_PARM_DESC(key, "This is the symetric key used to cypher and decypher de data.");

static int    majorNumber;                  ///< Stores the device number -- determined automatically
static char   message[BUFFER_SIZE] = {0};   ///< Memory for the string that is passed from userspace
static short  size_of_message;              ///< Used to remember the size of the string stored
static struct class*  cryptocharClass  = NULL; ///< The device-driver class struct pointer
static struct device* cryptocharDevice = NULL; ///< The device-driver device struct pointer

// The prototype functions for the character driver -- must come before the struct definition
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);
static int bgmr_cipher(char *sentence, int encrypt);

/** @brief Devices are represented as file structure in the kernel. The file_operations structure from
 *  /linux/fs.h lists the callback functions that you wish to associated with your file operations
 *  using a C99 syntax structure. char devices usually implement open, read, write and release calls
 */
static struct file_operations fops = {
    .read = dev_read,
    .write = dev_write
};

/** @brief The LKM initialization function
 *  The static keyword restricts the visibility of the function to within this C file. The __init
 *  macro means that for a built-in driver (not a LKM) the function is only used at initialization
 *  time and that it can be discarded and its memory freed up after that point.
 *  @return returns 0 if successful
 */
static int __init init_crypto(void) {
    printk(KERN_INFO "CryptoDevice: Initializing the CryptoDevice\n");

    // Try to dynamically allocate a major number for the device -- more difficult but worth it
    majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
    if (majorNumber < 0) {
        printk(KERN_ALERT "CryptoDevice failed to register a major number\n");
        return majorNumber;
    }
    printk(KERN_INFO "CryptoDevice: registered correctly with major number %d\n", majorNumber);

    // Register the device class
    cryptocharClass = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(cryptocharClass)) {                // Check for error and clean up if there is
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT "Failed to register device class\n");
        return PTR_ERR(cryptocharClass);          // Correct way to return an error on a pointer
    }
    printk(KERN_INFO "CryptoDevice: device class registered correctly\n");

    // Register the device driver
    cryptocharDevice = device_create(cryptocharClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
    if (IS_ERR(cryptocharDevice)) {               // Clean up if there is an error
        class_destroy(cryptocharClass);           // Repeated code but the alternative is goto statements
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT "Failed to create the device\n");
        return PTR_ERR(cryptocharDevice);
    }
    printk(KERN_INFO "CryptoDevice: device class created correctly\n"); // Made it! device was initialized

    printk(KERN_INFO "The key is: %s\n", key);
    
    return 0;
}

/** @brief The LKM cleanup function
 *  Similar to the initialization function, it is static. The __exit macro notifies that if this
 *  code is used for a built-in driver (not a LKM) that this function is not required.
 */
static void __exit exit_crypto(void) {
    device_destroy(cryptocharClass, MKDEV(majorNumber, 0));     // remove the device
    class_unregister(cryptocharClass);                          // unregister the device class
    class_destroy(cryptocharClass);                             // remove the device class
    unregister_chrdev(majorNumber, DEVICE_NAME);             // unregister the major number
    printk(KERN_INFO "CryptoDevice: Goodbye from Bruno, Giuliana, Matheus & Roger!\n");
}

/** @brief This function is called whenever device is being read from user space i.e. data is
 *  being sent from the device to the user. In this case it uses the copy_to_user() function to
 *  send the buffer string to the user and captures any errors.
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 *  @param buffer The pointer to the buffer to which this function writes the data
 *  @param len The length of the b
 *  @param offset The offset if required
 */
static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset) {
    int errorCount = 0;
    // copy_to_user has the format ( * to, *from, size) and returns 0 on success
    errorCount = copy_to_user(buffer, message, size_of_message);

    if (errorCount==0) {            // if true then have success
        printk(KERN_INFO "CryptoDevice: Sent %d characters to the user\n", size_of_message);
        return (size_of_message=0);  // clear the position to the start and return 0
    } else {
        printk(KERN_INFO "CryptoDevice: Failed to send %d characters to the user\n", errorCount);
        return -EFAULT;              // Failed -- return a bad address message (i.e. -14)
    }
}

/** @brief This function is called whenever the device is being written to from user space i.e.
 *  data is sent to the device from the user. The data is copied to a local buffer so it can be
 *  handled by the kernel. Then it's parsed, interpreted, and the proper operation function is
 *  called (cypher, decypher, hash). The result is saved in a message[] array in this LKM.
 *  @param filep A pointer to a file object
 *  @param buffer The buffer to that contains the string to write to the device
 *  @param len The length of the array of data that is being passed in the const char buffer
 *  @param offset The offset if required
 */
static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset) {
    char kernelBuffer[len], operation, space, sentence[len-2];
    int errorCount = copy_from_user(kernelBuffer, buffer, len);

    if (errorCount != 0) {
        printk(KERN_INFO "CryptoDevice: Failed to receive %d characters from the user\n", errorCount);
        return -EFAULT;              // Failed -- return a bad address message (i.e. -14)
    }

    operation = kernelBuffer[0];
    space = kernelBuffer[1];
    strncpy(sentence, kernelBuffer+2, sizeof(sentence));

    if (space != ' ') {
        printk(KERN_INFO "CryptoDevice: Failed to parse the operation: %s\n", buffer);
        return 0;
    }

    if (operation == 'c') {
        printk(KERN_INFO "CryptoDevice: Cypher\n");
        bgmr_cipher(sentence, 1);
    } else if (operation == 'd') {
        printk(KERN_INFO "CryptoDevice: Decypher\n");
        bgmr_cipher(sentence, 0);
    } else if (operation == 'h') {
        // TODO: hash message (modify the sentence)
        printk(KERN_INFO "CryptoDevice: Hash\n");
    } else {
        printk(KERN_INFO "CryptoDevice: Failed to parse the operation: %s\n", buffer);
        return 0;
    }
    printk(KERN_INFO "CryptoDevice: Received %zu characters from the user with the data %s...\n", len, sentence);
    return len;
}

/** @brief A module must use the module_init() module_exit() macros from linux/init.h, which
 *  identify the initialization function at insertion time and the cleanup function (as
 *  listed above)
 */
module_init(init_crypto);
module_exit(exit_crypto);





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
        rc = crypto_skcipher_encrypt(sk->req);
    } else {
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
    int ret = -EFAULT;
    
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

    if (crypto_skcipher_setkey(skcipher, key, strlen(key))) {
        pr_info("key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }

    sk.tfm = skcipher;
    sk.req = req;

    int i;
    int sentenceLength = strlen(sentence);
    int numberOfBlocks = sentenceLength % 1 == 0 ? sentenceLength/16 : (int)sentenceLength/16 + 1; // Sentence length is alwaus >= 0
    for (i = 0; i < sentenceLength; i++) {
        sg_init_one(&sk.sg, sentence[i*16], 16);
        skcipher_request_set_crypt(req, &sk.sg, &sk.sg, 16, "dummyRandomData!");
        init_completion(&sk.result.completion);

        /* Encrypt Data */
        ret = test_skcipher_encdec(&sk, encrypt);
        if (ret) { goto out; }

        pr_info("Encrypted %ld/%ld \n", (long)i+1, (long)numberOfBlocks);

        sg_copy_to_buffer(&sk.sg, 1, &message[i*16], 16); // TODO: copy while number of bytes copied < total bytes
    }

    pr_info("Encryption triggered successfully\n");
out:
    if (skcipher) {
        crypto_free_skcipher(skcipher);
    }
    if (req) {
        skcipher_request_free(req);
    }
    return ret;
}
