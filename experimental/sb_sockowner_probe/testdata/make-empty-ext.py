# -*- coding: utf-8 -*-
"""构造一个"扩展版本表存在但为空"的 .ko，用于反向测试 verify-ko.py 的闸门。

这是最危险的一种模块形态，比完全没有版本表更危险：看起来两张表齐全，实际
一张也不生效。因为 check_version() 判断的是 if (info->index.vers_ext_crc)
——节索引是否存在，而不是长度。段存在但长度为零时，内核照样走扩展路径、
迭代零个条目、pr_warn_once 然后 return 1，结果是所有符号一个都不校验，
而且不会回退到 __versions。

本脚本只把 __version_ext_crcs 的节头 sh_size 改成 0，其余一概不动。

用法:
    python make-empty-ext.py <正常的.ko> <输出.ko> __version_ext_crcs
    python ../verify-ko.py <输出.ko> ../target/Module.symvers.device
    # 期望：被拒绝，退出码 1
"""
import struct, shutil, sys

src, dst, target = sys.argv[1], sys.argv[2], sys.argv[3]
shutil.copyfile(src, dst)
blob = bytearray(open(dst, 'rb').read())

shoff, = struct.unpack_from('<Q', blob, 0x28)
entsize, count, strndx = struct.unpack_from('<HHH', blob, 0x3A)
str_off = struct.unpack_from('<IIQQQQ', blob, shoff + strndx * entsize)[4]

for index in range(count):
    base = shoff + index * entsize
    name_off = struct.unpack_from('<I', blob, base)[0]
    start = str_off + name_off
    name = blob[start:blob.index(b'\0', start)].decode()
    if name == target:
        struct.pack_into('<Q', blob, base + 32, 0)   # Elf64_Shdr.sh_size @32
        open(dst, 'wb').write(blob)
        print('已把 %s 的 sh_size 置零 -> %s' % (target, dst))
        break
else:
    raise SystemExit('找不到节 %s' % target)
