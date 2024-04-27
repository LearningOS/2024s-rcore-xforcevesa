# ch3报告

## ch3实验总结

为实现sys_task_info，本人针对TCB模块注入了TaskInfo，做了一部分略具破坏性的改动：将TCB的```task_status```字段改为```task_info```。此外，对当前进程的syscall行为进行监视，调用时触发相应桶计数。最后对于应用软件运行时间，本人采用加入字段的方式记录开始运行时此task的时间戳，并记录直到发生sys_task_info时的时长。


