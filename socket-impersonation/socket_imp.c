#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/namei.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/tcp.h>
#include <linux/inet.h>
#include <linux/slab.h>
#include <linux/in.h>
#include <linux/vm_sockets.h>

#define PARENT_INSTANCE_CID 3
#define ENCLAVE_CID 16
#define VSOCK_CID_ANY 0xFFFFFFFF
#define VSOCK_PORT 5001
#define SOME_PORT 49576

static unsigned long * __sys_call_table;

typedef asmlinkage long (*orig_mkdir_t)(const char __user *pathname, umode_t mode);
orig_mkdir_t orig_mkdir;
typedef asmlinkage long (*orig_socket_t)(int, int, int);
orig_socket_t orig_socket;
typedef asmlinkage long (*orig_getpeername_t)(int, struct sockaddr __user *, int __user *);
orig_getpeername_t orig_getpeername;
typedef asmlinkage long (*orig_getsockname_t)(int, struct sockaddr __user *, int __user *);
orig_getsockname_t orig_getsockname;
typedef asmlinkage long (*orig_setsockopt_t)(int fd, int level, int optname,
    char __user *optval, int optlen);
orig_setsockopt_t orig_setsockopt;
typedef asmlinkage long (*orig_getsockopt_t)(int fd, int level, int optname,
    char __user *optval, int __user *optlen);
orig_getsockopt_t orig_getsockopt;
typedef asmlinkage long (*orig_bind_t)(int, struct sockaddr __user *, int);
orig_bind_t orig_bind;
typedef asmlinkage long (*orig_listen_t)(const struct pt_regs *);
orig_listen_t orig_listen;
typedef asmlinkage long (*orig_accept_t)(int, struct sockaddr __user *, int __user *);
orig_accept_t orig_accept;
typedef asmlinkage long (*orig_accept4_t)(int, struct sockaddr __user *, int __user *, int);
orig_accept4_t orig_accept4;
typedef asmlinkage long (*orig_connect_t)(int, struct sockaddr __user *, int);
orig_connect_t orig_connect;
typedef asmlinkage long (*orig_recvfrom_t)(int, void __user *, size_t, unsigned,
				struct sockaddr __user *, int __user *);
orig_recvfrom_t orig_recvfrom;
typedef asmlinkage long (*orig_sendto_t)(int, void __user *, size_t, unsigned,
				struct sockaddr __user *, int);
orig_sendto_t orig_sendto;

int hooked_fd;

/* The built in linux write_cr0() function stops us from modifying
 * the WP bit, so we write our own instead */
inline void cr0_write(unsigned long cr0)
{
    asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}

/* Bit 16 in the cr0 register is the W(rite) P(rotection) bit which
 * determines whether read-only pages can be written to. We are modifying
 * the syscall table, so we need to unset it first */
static inline void protect_memory(void)
{
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);
    cr0_write(cr0);
}

static inline void unprotect_memory(void)
{
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);
    cr0_write(cr0);
}

asmlinkage int hook_mkdir(const char __user *pathname, umode_t mode)
{
    char dir_name[NAME_MAX] = {0};

    long error = strncpy_from_user(dir_name, pathname, NAME_MAX);

    if (error > 0)
        printk(KERN_INFO "rootkit: Trying to create directory with name: %s\n", dir_name);
    printk(KERN_INFO "rootkit: Trying to create directory \n");

    orig_mkdir(pathname, mode);
    return 0;
}

asmlinkage int hook_socket(int domain, int type, int protocol)
{
    if (domain == AF_INET)
        return orig_socket(AF_VSOCK, type, 0);
    else
        return orig_socket(domain, type, protocol);
}

asmlinkage int hook_getsockname(int sockfd, struct sockaddr __user * addr, int __user * addrlen)
{
    long ret;
    struct sockaddr_in new_addr;

    new_addr.sin_family = AF_INET;
    new_addr.sin_port = htons(8000);
    new_addr.sin_addr.s_addr = htonl(in_aton("0.0.0.0"));
    memset(&new_addr.sin_zero, 0, 8);

    pr_info("Perform getsockname.\n");

    ret = orig_getsockname(sockfd, addr, addrlen);

    copy_to_user(addr, &new_addr, sizeof(struct sockaddr));

    return ret;
}

asmlinkage int hook_getpeername(int sockfd, struct sockaddr __user * addr, int __user * addrlen)
{
    long ret;
    struct sockaddr_in new_addr;

    new_addr.sin_family = AF_INET;
    new_addr.sin_port = htons(SOME_PORT);
    new_addr.sin_addr.s_addr = htonl(in_aton("0.0.0.0"));
    memset(&new_addr.sin_zero, 0, 8);

    pr_info("Perform getpeername.\n");

    ret = orig_getpeername(sockfd, addr, addrlen);

    copy_to_user(addr, &new_addr, sizeof(struct sockaddr));

    return ret;
}

asmlinkage int hook_setsockopt(int fd, int level, int optname,
				char __user *optval, int optlen)
{
    pr_info("Skipping setsockopt.\n");
    if (optname == TCP_CONGESTION)
        return orig_setsockopt(fd, SOL_SOCKET, optname, optval, optlen);
    return 0;
}

asmlinkage int hook_getsockopt(int fd, int level, int optname,
				char __user *optval, int __user *optlen)
{
    pr_info("Skipping getsockopt.\n");
    return 0;
}

asmlinkage int hook_bind(int sockfd, struct sockaddr __user * addr, int addrlen)
{
    struct sockaddr_vm sockaddr_vm;
    sa_family_t orig_family;

    pr_info("Custom socket binding...\n");
    copy_from_user(&orig_family, addr, sizeof(sa_family_t));

    if (orig_family == AF_INET || orig_family == AF_INET6) {
        pr_info("Changing sockaddr.\n");
        sockaddr_vm.svm_family = AF_VSOCK;
        sockaddr_vm.svm_reserved1 = 0;
        sockaddr_vm.svm_port = VSOCK_PORT;
        sockaddr_vm.svm_cid = ENCLAVE_CID;
        memset(&sockaddr_vm.svm_zero, 0, sizeof(struct sockaddr) -
                    sizeof(sa_family_t) -
                    sizeof(unsigned short) -
                    sizeof(unsigned int) - sizeof(unsigned int));
        pr_info("Completed sockaddr\n");

        copy_to_user(addr, &sockaddr_vm, sizeof(struct sockaddr));

        hooked_fd = sockfd;
    }

    return orig_bind(sockfd, addr, addrlen);
}

asmlinkage int hook_listen(const struct pt_regs *regs)
{
    return 0;
}

asmlinkage int hook_accept(int sockfd, struct sockaddr __user * addr, int __user * addrlen)
{
    pr_info("Simple accept.\n");
    return orig_accept(sockfd, NULL, NULL);
}

// TODO: Return at the end, find way to change the given address and return another. Kprobe?
asmlinkage int hook_accept4(int sockfd, struct sockaddr __user * addr, int __user * addrlen, int flags)
{
    struct sockaddr_vm sockaddr_vm;
    short orig_port;
    int addrlen_vm = sizeof(struct sockaddr);
    long ret;
    pr_info("Custom accept4.\n");

    ret = orig_accept4(sockfd, addr, addrlen, flags);

    if (sockfd == hooked_fd) {
        pr_info("Changing returned sockaddr.\n");
        sockaddr_vm.svm_family = AF_INET;
        copy_to_user(addr, &sockaddr_vm.svm_family, sizeof(sa_family_t));
        copy_to_user(addrlen, &addrlen_vm, sizeof(int));
    }
    
    return ret;
}

/* Replace address family acgument of the syscall */
asmlinkage int hook_connect(int sockfd, struct sockaddr __user *addr, int addrlen)
{
    /* TODO: if not working, try copying to userspace */
    /* Get sockaddr argument form 2nd register */
    sa_family_t orig_family;
    struct sockaddr_vm sockaddr_vm;
    pr_info("Custom connect.\n");

    copy_from_user(&orig_family, addr, sizeof(sa_family_t));

    if (orig_family == AF_INET) {
        sockaddr_vm.svm_family = AF_VSOCK;
        sockaddr_vm.svm_reserved1 = 0;
        sockaddr_vm.svm_port = VSOCK_PORT;
        sockaddr_vm.svm_cid = PARENT_INSTANCE_CID;
        memset(&sockaddr_vm.svm_zero, 0, sizeof(struct sockaddr) -
                    sizeof(sa_family_t) -
                    sizeof(unsigned short) -
                    sizeof(unsigned int) - sizeof(unsigned int));
        pr_info("Completed sockaddr\n");

        copy_to_user(addr, &sockaddr_vm, sizeof(struct sockaddr));
    }

    return orig_connect(sockfd, addr, addrlen);
}

asmlinkage int hook_recvfrom(int sockfd, void __user *buff, size_t len, unsigned flags,
				struct sockaddr __user * src_addr, int __user * addrlen)
{
    pr_info("Received message of length: %d\n", len);
    return orig_recvfrom(sockfd, buff, len, flags, src_addr, addrlen);
}

asmlinkage int hook_sendto(int sockfd, void __user *buf, size_t len, unsigned flags,
				struct sockaddr __user *dest_addr, int addrlen)
{
    return orig_sendto(sockfd, buf, len, 0, dest_addr, addrlen);
}

static int __init rootkit_init(void)
{
    __sys_call_table = kallsyms_lookup_name("sys_call_table");

    printk(KERN_INFO "rootkit: Grabbed syscall\n");
    printk(KERN_DEBUG "rootkit: Found the syscall table at 0x%lx\n", __sys_call_table);

    orig_mkdir = (orig_mkdir_t)__sys_call_table[__NR_mkdir];
    orig_connect = (orig_connect_t)__sys_call_table[__NR_connect];
    orig_socket = (orig_socket_t)__sys_call_table[__NR_socket];
    orig_sendto = (orig_sendto_t)__sys_call_table[__NR_sendto];
    orig_bind = (orig_bind_t)__sys_call_table[__NR_bind];
    orig_accept = (orig_accept_t)__sys_call_table[__NR_accept];
    orig_accept4 = (orig_accept4_t)__sys_call_table[__NR_accept4];
    orig_getsockname = (orig_getsockname_t)__sys_call_table[__NR_getsockname];
    orig_getpeername = (orig_getpeername_t)__sys_call_table[__NR_getpeername];
    orig_setsockopt = (orig_setsockopt_t)__sys_call_table[__NR_setsockopt];
    orig_getsockopt = (orig_getsockopt_t)__sys_call_table[__NR_getsockopt];
    orig_recvfrom = (orig_recvfrom_t)__sys_call_table[__NR_recvfrom];

    printk(KERN_INFO "rootkit: Loaded\n");
    printk(KERN_DEBUG "rootkit: Found the syscall table at 0x%lx\n", __sys_call_table);

    unprotect_memory();

    __sys_call_table[__NR_mkdir] = (unsigned long)hook_mkdir;
    __sys_call_table[__NR_connect] = (unsigned long)hook_connect;
    __sys_call_table[__NR_socket] = (unsigned long)hook_socket;
    __sys_call_table[__NR_sendto] = (unsigned long)hook_sendto;
    __sys_call_table[__NR_bind] = (unsigned long)hook_bind;
    __sys_call_table[__NR_accept] = (unsigned long)hook_accept;
    __sys_call_table[__NR_accept4] = (unsigned long)hook_accept4;
    __sys_call_table[__NR_getsockname] = (unsigned long)hook_getsockname;
    __sys_call_table[__NR_getpeername] = (unsigned long)hook_getpeername;
    __sys_call_table[__NR_setsockopt] = (unsigned long)hook_setsockopt;
    __sys_call_table[__NR_getsockopt] = (unsigned long)hook_getsockopt;
    __sys_call_table[__NR_recvfrom] = (unsigned long)hook_recvfrom;

    protect_memory();

    return 0;
}

static void __exit rootkit_exit(void)
{
    unprotect_memory();
    
    __sys_call_table[__NR_mkdir] = (unsigned long)orig_mkdir;
    __sys_call_table[__NR_connect] = (unsigned long)orig_connect;
    __sys_call_table[__NR_socket] = (unsigned long)orig_socket;
    __sys_call_table[__NR_sendto] = (unsigned long)orig_sendto;
    __sys_call_table[__NR_bind] = (unsigned long)orig_bind;
    __sys_call_table[__NR_accept] = (unsigned long)orig_accept;
    __sys_call_table[__NR_accept4] = (unsigned long)orig_accept4;
    __sys_call_table[__NR_getsockname] = (unsigned long)orig_getsockname;
    __sys_call_table[__NR_getpeername] = (unsigned long)orig_getpeername;
    __sys_call_table[__NR_setsockopt] = (unsigned long)orig_setsockopt;
    __sys_call_table[__NR_getsockopt] = (unsigned long)orig_getsockopt;
    __sys_call_table[__NR_recvfrom] = (unsigned long)orig_recvfrom;
    protect_memory();
    
    printk(KERN_INFO "rootkit: Unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Raul Moldovan");
MODULE_DESCRIPTION("Syscall Table Hijacking");
