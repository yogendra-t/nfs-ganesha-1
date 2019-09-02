OPTIONS="-L /var/log/ganesha.log -f /etc/ganesha/ganesha.conf -N NIV_EVENT"
EPOCH_EXEC="@LIBEXECDIR@/ganesha/gpfs-epoch"
#ENV_OPTIONS="ASAN_OPTIONS=alloc_dealloc_mismatch=true:print_stats=true:atexit=true:start_deactivated=false:print_cmdline=true:quarantine_size_mb=1:detect_leaks=false:abort_on_error=true:disable_coredump=false:verbosity=2:log_path=/tmp/asan.log:log_exe_name=1"
ENV_OPTIONS="LD_PRELOAD='/usr/lib64/ganesha/libganesha_trace.so /lib64/libdl.so.2'"
