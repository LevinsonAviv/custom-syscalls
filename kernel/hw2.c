#include <linux/kernel.h>
#include <linux/sched.h>
#include <asm/current.h>
#include <linux/capability.h>
#include <linux/errno.h>
#include <asm/unistd.h>

#define BAN_GETPID 0b00000001
#define BAN_PIPE 0b00000010
#define BAN_KILL 0b00000100
#define BAN_SIGNAL 0b00001000

static char get_flag_from_char(char ban){
	switch(ban){
		case 'g':
			return BAN_GETPID;
		case 'p':
			return BAN_PIPE;
		case 'k':
			return BAN_KILL;
		case 's':
			return BAN_SIGNAL;
		default:
			return 0;
	}	
}

static char get_flag_from_nr(unsigned long nr){
	switch(nr){
		case __NR_getpid:
			return BAN_GETPID;
		case __NR_pipe:
			return BAN_PIPE;
		case __NR_kill:
			return BAN_KILL;
		case __NR_rt_sigaction:
			return BAN_SIGNAL;
		default:
			return 0;
	}	
}

asmlinkage long sys_hello(void) {
	printk("Hello, World!\n");
	return 0;
}

asmlinkage long sys_set_ban(int ban_getpid, int ban_pipe, int ban_kill, int ban_sig) {
	char banned_syscalls = 0b00000000;
	if(ban_getpid < 0 || ban_pipe < 0 || ban_kill < 0 || ban_sig < 0){
		return -EINVAL;
	}
	if(!capable(CAP_SYS_ADMIN)){
		return -EPERM;
	}
	if(ban_getpid >= 1){
		banned_syscalls |= BAN_GETPID;
	}
	if(ban_pipe >= 1){
		banned_syscalls |= BAN_PIPE;
	}
	if(ban_kill >= 1){
		banned_syscalls |= BAN_KILL;
	}
	if(ban_sig >= 1){
		banned_syscalls |= BAN_SIGNAL;
	}
	current->banned_syscalls = banned_syscalls;
	return 0;
}

asmlinkage long sys_get_ban(char ban) {
	char flag = get_flag_from_char(ban);
	if(flag == 0){
		return -EINVAL;
	}
	return (current->banned_syscalls & flag) != 0;
}

long get_ban_by_nr(unsigned long nr){
	char flag = get_flag_from_nr(nr);
	return (current->banned_syscalls & flag) != 0;
}

asmlinkage long sys_check_ban(pid_t pid, char ban) {
	struct task_struct *other_task = NULL;
	char flag = get_flag_from_char(ban);
	if(flag == 0){
		return -EINVAL;
	}
	other_task = find_task_by_vpid(pid);
	if(other_task == NULL){
		return -ESRCH;
	}
	if((current->banned_syscalls & flag) != 0){
		return -EPERM;
	}
	return (other_task->banned_syscalls & flag) != 0;
}

asmlinkage long sys_flip_ban_branch(int height, char ban) {
	long banned_count = 0;
	struct task_struct *parent_task = NULL;
	char flag = get_flag_from_char(ban);
	if(height <= 0 || flag == 0){
		return -EINVAL;
	}
	if((current->banned_syscalls & flag) != 0){
		return -EPERM;
	}
	parent_task = current->real_parent;
	while(parent_task != NULL && height > 0){
		parent_task->banned_syscalls ^= flag;
		if((parent_task->banned_syscalls & flag) != 0){
			banned_count++;
		}
		if(is_global_init(parent_task)){
			break;
		}
		parent_task = parent_task->real_parent;
		height--;
	}
	return banned_count;
}
