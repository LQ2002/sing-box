#!/system/bin/sh
# 卸载模块时把内核里的实例也卸掉，避免"模块文件没了但代码还在内核里"的状态。
# rmmod 失败不做处理：可能正在被使用，重启后自然就不在了。
rmmod sb_sockowner_probe 2>/dev/null
exit 0
