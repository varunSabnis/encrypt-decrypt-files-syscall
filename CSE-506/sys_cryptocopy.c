#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/crypto.h>
#include <linux/slab.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/random.h>
#include <crypto/hash.h>
#include <asm/current.h>
#include <linux/string.h>
#include "syscall_struct.h"


asmlinkage extern long (*sysptr)(void *arg);

int check_user_arg(void* user_arg, int size){

	if (!user_arg){
		printk("User arg is not passed !!");
		return -EINVAL;
	} 

	if (!access_ok(user_arg, size)){
		printk("Access to user args is not a valid translation");
		return -EFAULT;
	}

	return 0;
}

int get_cipherkey_hash(void* key, unsigned int cipher_length, void* cipherkey_hash){


	int ret = 0;
	struct shash_desc *shash = NULL;
	struct crypto_shash *tfm = NULL;

	memset(cipherkey_hash, 0, SHA256_LEN);
	tfm = crypto_alloc_shash("sha256", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)) {
		printk(KERN_DEBUG "Could not create tfm for sha256\n");
		ret = PTR_ERR(tfm);
		goto clean_hash;
	}

	shash = (struct shash_desc*)kmalloc(crypto_shash_descsize(tfm) + sizeof(struct shash_desc), GFP_KERNEL);
	if (shash == NULL) {
		ret = -ENOMEM;
		goto clean_hash;
	}

	shash->tfm =  tfm;
	ret = crypto_shash_digest(shash, (u8 *)key, cipher_length, (u8 *)cipherkey_hash);
	if (ret < 0) {
		printk(KERN_DEBUG "Failed to hash key");
		goto clean_hash;
	}

	clean_hash:
		if (shash != NULL){
			shash->tfm = NULL;
			kfree(shash);
		}
		if (tfm != NULL){
			crypto_free_shash(tfm);
		}

	return ret;

}

int add_preamble(struct file* fptr, int hashkey_len, void* hashkey){

	if (kernel_write(fptr, hashkey, (ssize_t)hashkey_len, &fptr->f_pos) < 0) {
		 return -1;
	}

	return 0;
}

int verify_preamble(struct file* fptr, int hashkey_len, void* hashkey){

	void* file_hashkey = NULL;
	int ret = 0;
	int read_size;

	file_hashkey = kmalloc(hashkey_len, GFP_KERNEL);

	if (file_hashkey == NULL){
		goto preamble_check;
	}

	if ((read_size = kernel_read(fptr, file_hashkey, (ssize_t)hashkey_len, &fptr->f_pos)) < 0){
		ret = read_size; 
		goto preamble_check;
	}	
	if (memcmp(file_hashkey, hashkey, hashkey_len)) {
		printk("Hash of key doesn't match preamble\n");
		ret = -EACCES;
		goto preamble_check;
	}

	preamble_check:
		if (file_hashkey)
		   kfree(file_hashkey);
		 
	return ret;
}


int get_file_stat(const char *file_name, struct kstat *file_stat)
{
	mm_segment_t old_fs;
	int ret;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = vfs_stat(file_name, file_stat);
	set_fs(old_fs);
	return ret;
}


void unlink_file(struct file* fptr)
{	
	mm_segment_t old_fs;

	filp_close(fptr, NULL);
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	inode_lock(fptr->f_path.dentry->d_parent->d_inode);
	vfs_unlink(fptr->f_path.dentry->d_parent->d_inode, fptr->f_path.dentry, NULL);
	inode_unlock(fptr->f_path.dentry->d_parent->d_inode);
	set_fs(old_fs);	
}

int rename_file(struct file* src_fptr, struct file* dest_fptr){
	mm_segment_t old_fs;
	int ret;
	printk("Renaming temp filename with output filename");
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = vfs_rename(src_fptr->f_path.dentry->d_parent->d_inode, src_fptr->f_path.dentry, 
					 dest_fptr->f_path.dentry->d_parent->d_inode, dest_fptr->f_path.dentry, NULL, 0);
	set_fs(old_fs);	

	return ret;
}

int encrypt_or_decrypt_data(struct skcipher_request* req, void* buf, ssize_t buf_len, unsigned char flag){
	
	int ret = 0;
	struct scatterlist *sg = NULL;
	struct crypto_wait* result = NULL;
	void* ivdata = NULL;

	result = (struct crypto_wait*) kmalloc(sizeof(struct crypto_wait), GFP_KERNEL);
	if (result == NULL){
		ret =  -ENOMEM;
		goto clean_encrypt_decrypt;
	}

	ivdata = kmalloc(16, GFP_KERNEL);
	if (ivdata == NULL) {
		ret =  -ENOMEM;
		goto clean_encrypt_decrypt;
	}

    memset(ivdata, 0, 16);

	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, result);

	sg = (struct scatterlist*) kmalloc(sizeof(struct scatterlist), GFP_KERNEL);
	if (sg == NULL) {
		ret =  -ENOMEM;
		goto clean_encrypt_decrypt;
	}

	sg_init_one(sg, buf, buf_len);
	skcipher_request_set_crypt(req, sg, sg, buf_len, ivdata);
	crypto_init_wait(result);

	if (flag & 0x1) {
		ret = crypto_wait_req(crypto_skcipher_encrypt(req), result);
	}

	if (flag & 0x2) {
		ret = crypto_wait_req(crypto_skcipher_decrypt(req), result);
	}

	clean_encrypt_decrypt:
		if (sg)
			kfree(sg);
		if (result)
		    kfree(result);
		if (ivdata)
		    kfree(ivdata);

	return ret;
}

int read_write_file(struct file* in_fptr, struct file* out_fptr, unsigned int flag, void* cipherkey, unsigned int cipherkey_len){
	
	void* buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	ssize_t read_size, write_size;
	struct crypto_skcipher *skcipher = NULL;
	struct skcipher_request *req = NULL;
	int ret = 0;

	if ((flag & 0x1) || (flag & 0x2)) {
		
		skcipher = crypto_alloc_skcipher("ctr-aes-aesni", 0, 0);
		if (IS_ERR(skcipher)) {
			ret = PTR_ERR(skcipher);
			goto clean_read_write;
		}
		req = skcipher_request_alloc(skcipher, GFP_KERNEL);
		if (!req) {
			ret = -ENOMEM;
			goto clean_read_write;
		}
		if (crypto_skcipher_setkey(skcipher, cipherkey, cipherkey_len)) {
			printk("Failed to set cipher key");
			ret = -EAGAIN;
			goto clean_read_write;
		}
	}

	while((read_size = kernel_read(in_fptr, buf, PAGE_SIZE, &in_fptr->f_pos)) > 0){

		if ((flag & 0x1) | (flag & 0x2)){
			ret = encrypt_or_decrypt_data(req, buf, read_size, flag);
			if (ret < 0){
				printk("Failed to encrpyt / Decrypt\n");
				goto clean_read_write;
			}
		}
		write_size = kernel_write(out_fptr, buf, read_size, &out_fptr->f_pos);
		if (write_size < 0){
			ret = -1;
			goto clean_read_write;
		}

	}
    
	clean_read_write:
	       if (buf != NULL){
			   kfree(buf);
		   }
		   // Should delete if partial write
		   if ((flag & 0x1) | (flag & 0x2)){

			   kfree(req);
			   if (skcipher){
				   crypto_free_skcipher(skcipher);
			   }
		   }

	return ret;
}

asmlinkage long cryptocopy(void *arg)
{

	struct sysargs* kargs_cp = NULL;
	struct file *in_filp = NULL, *out_filp = NULL, *tmp_out_filp = NULL; // pointing to a file
	struct filename *kernel_infile = NULL, *kernel_outfile = NULL; // Will hold the filename in kernel
	struct kstat *kinfile_stat = NULL, *koutfile_stat = NULL;
	void* cipherkey_hash = NULL;
	char* tmp_outfile_name = NULL;
	unsigned int cipher_len;
	unsigned char flag;
	int ret = 0, outfile_stat_ret = 1;
	bool outfile_exists = false;


	ret = check_user_arg(arg, sizeof(struct sysargs));

	if (ret < 0){
	   printk("Error in check user arg");
	   goto clean;
	}

	// Allocate memory for structure in kernel
	kargs_cp = (struct sysargs*)kmalloc(sizeof(struct sysargs), GFP_KERNEL);

	if (kargs_cp == NULL) {
		ret = -ENOMEM;
		goto clean;
	}
	
	kargs_cp->cipher = NULL;
    
	// Copying structure from user land to kernel
	if (copy_from_user(kargs_cp, arg, sizeof(struct sysargs))){

		ret = -EFAULT;
		goto clean;
	}

    // Add support to copy filename from arg->infile pointer to kargs_cp->infile 
	printk("Flag %u", kargs_cp->flag);
	printk("Cipher Length %d", kargs_cp->cipher_len);

	
	flag = kargs_cp->flag;
	if ((flag & 0x1) || (flag & 0x2)){
		cipher_len = kargs_cp->cipher_len;
		ret = check_user_arg(((struct sysargs *)arg)->cipher,cipher_len);
		if (ret < 0){
			printk("User arg cipher validation failed");
			goto clean;
		}

		kargs_cp->cipher = kmalloc(cipher_len, GFP_KERNEL);

		if (kargs_cp->cipher == NULL){
			printk("Cipher memory not allocated");
			ret = -ENOMEM;
			goto clean;
		}

		if (copy_from_user(kargs_cp->cipher,((struct sysargs*)arg)->cipher, 
						  cipher_len)){
							  printk("Error in copying cipher");
							  ret = -EFAULT;
							  goto clean;
						  }
		cipherkey_hash = kmalloc(SHA256_LEN, GFP_KERNEL);

		if (cipherkey_hash == NULL){
			printk("Failed to allocate memory of cipherkey hash");
			ret = -ENOMEM;
			goto clean;
		}

		ret = get_cipherkey_hash(kargs_cp->cipher, cipher_len, cipherkey_hash);
		
		if(ret < 0){
			printk("Failed to get hash of cipher key");
			goto clean;
		}

	}

	kernel_infile = getname(((struct sysargs *)arg)->infile);
	printk("Input File name %s", kernel_infile->name);

	if (IS_ERR(kernel_infile)){
		printk("Failed to copy input filename to kernel memory");
		ret = PTR_ERR(kernel_infile);
		goto clean;
	}
	
	// input file stat
	kinfile_stat = kmalloc(sizeof(struct kstat), GFP_KERNEL);
	if (!kinfile_stat) {
		ret = -ENOMEM;
		goto clean;
	}

	ret = get_file_stat(kernel_infile->name, kinfile_stat);
	if (ret < 0) {
		printk("Could not stat non-existent file");
		goto clean;
	}

	/* check if input file is regular file or not*/
	if (!S_ISREG(kinfile_stat->mode) ) {
		printk("Read/Write only to regular files");
		ret = -EINVAL;
		goto clean;
	}

	
	in_filp = filp_open(kernel_infile->name, O_RDONLY, 0);
	if(IS_ERR(in_filp)){
		printk("Error in openning input file for reading");
		ret = PTR_ERR(in_filp);
		goto clean;
	}

	kernel_outfile = getname(((struct sysargs *)arg)->outfile);
	printk("Output File name %s", kernel_outfile->name);

	if (IS_ERR(kernel_outfile)){
		printk("Failed to copy input filename to kernel memory");
		ret = PTR_ERR(kernel_outfile);
		goto clean;
	}
	
	koutfile_stat = kmalloc(sizeof(struct kstat), GFP_KERNEL);
	if (!koutfile_stat) {
		ret = -ENOMEM;
		goto clean;
	}
	outfile_stat_ret = get_file_stat(kernel_outfile->name, koutfile_stat);
	if (!outfile_stat_ret) {

		outfile_exists = true;
		if (S_ISLNK(koutfile_stat->mode) ) {
			printk("Cannot copy content to symbolic link file");
			ret = -EINVAL;
			goto clean;
		}

		if (!S_ISREG(koutfile_stat->mode) ) {
			printk("Read/Write is only for regular files\n");
			ret = -EINVAL;
			goto clean;
		}

		if (koutfile_stat->ino == kinfile_stat->ino){
			printk("The inode numbers for both the files are same");
			ret = -EINVAL;
			goto clean;
		}
	    	
	} 


	out_filp = filp_open(kernel_outfile->name, O_WRONLY | O_TRUNC | O_CREAT, 0777);
	if(IS_ERR(out_filp)){
		printk("Error in openning input file for reading");
		ret = PTR_ERR(out_filp);
		goto clean;
		// goto
	}

	// Getting temp outfile name
	tmp_outfile_name = (char*)kmalloc(strlen(kernel_outfile->name) + 10, GFP_KERNEL);
	sprintf(tmp_outfile_name, "%s-%d", kernel_outfile->name, current->pid);

	// Opening temp outfile
	tmp_out_filp = filp_open((const char*)tmp_outfile_name, O_WRONLY | O_TRUNC | O_CREAT, 0777);
	if(IS_ERR(tmp_out_filp)){
		printk("Error in openning input file for reading");
		ret = PTR_ERR(tmp_out_filp);
		goto clean;
	}
	

	if (flag & 0x1){
		ret = add_preamble(tmp_out_filp, SHA256_LEN, cipherkey_hash);
		if (ret < 0){ 
			printk("Failed to add preamble to output file");
			goto clean_partial;
		}
	}

	if (flag & 0x2){
		
		ret = verify_preamble(in_filp, SHA256_LEN, cipherkey_hash);
		if (ret < 0){
			printk("Failed to verify preamble");
		    goto clean_partial;
		}
	}

	ret = read_write_file(in_filp, tmp_out_filp, flag, cipherkey_hash, SHA256_LEN);

	if (ret < 0){
		printk("Failed to perform copy with encrypt/decrypt operation");
		goto clean_partial;
	}
	
	out_filp->f_inode->i_mode = in_filp->f_inode->i_mode;

	ret = rename_file(tmp_out_filp, out_filp);
	if (ret < 0){
		printk("Failed to rename temporary file");
		goto clean_partial;
	}

	clean_partial:
		if (ret < 0){
			printk("Cleaning partial writes : Deleting temp and outfile");
			unlink_file(tmp_out_filp);
			tmp_out_filp = NULL;
			if (!outfile_exists) {
				unlink_file(out_filp);
				out_filp = NULL;
			}
		}
	
	clean:
		if (in_filp != NULL && !IS_ERR(in_filp)){
			printk(KERN_INFO "Cleanup: Infile Pointer");
			filp_close(in_filp, NULL);
		}
		if (kernel_infile != NULL && !IS_ERR(kernel_infile)){
			printk(KERN_INFO "Cleanup: Infile Name");
			putname(kernel_infile);
		}
		if (out_filp != NULL && !IS_ERR(out_filp)){
			printk(KERN_INFO "Cleanup: Outfile Pointer");
			filp_close(out_filp, NULL);
		}
		if (kernel_outfile != NULL && !IS_ERR(kernel_outfile)){
			printk(KERN_INFO "Cleanup: Outfile Name");
			putname(kernel_outfile);
		}
		if (kargs_cp != NULL){
			printk(KERN_INFO "Cleanup: kargs pointer");
			if (((struct sysargs *)kargs_cp)->cipher != NULL){
				printk(KERN_INFO "Cleanup: kargs cipher key");
				kfree(((struct sysargs *)kargs_cp)->cipher);
			}
			kfree(kargs_cp);
		}
		if (cipherkey_hash != NULL){
			printk(KERN_INFO "Cleanup: Cipher Key Hash");
			kfree(cipherkey_hash);
		}
		if (kinfile_stat != NULL){
			printk(KERN_INFO "Cleanup: Input File stat");
			kfree(kinfile_stat);
		}
		if (koutfile_stat != NULL){
			printk(KERN_INFO "Cleanup: Output File stat");
			kfree(koutfile_stat);
		}
		if (tmp_outfile_name != NULL){
			printk(KERN_INFO "Cleanup: File name with process ID");
			kfree(tmp_outfile_name);
		}
		if (tmp_out_filp != NULL && !IS_ERR(tmp_out_filp)){
			printk(KERN_INFO "Cleanup: Removing file pointer");
			kfree(tmp_out_filp);
		}
	
	//Doing stat to check read permissions for the infile.
	return (long)ret;
}

static int __init init_sys_cryptocopy(void)
{
	printk("installed new sys_cryptocopy module\n");
	if (sysptr == NULL)
		sysptr = cryptocopy;
	return 0;
}
static void  __exit exit_sys_cryptocopy(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_cryptocopy module\n");
}
module_init(init_sys_cryptocopy);
module_exit(exit_sys_cryptocopy);
MODULE_LICENSE("GPL");