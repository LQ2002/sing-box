# -*- coding: utf-8 -*-
"""OTA 后刷新内核 ABI 基准。

从一个 Android boot 镜像（或已解出的内核 Image）重建三样东西：

  1. Module.symvers.device  —— 权威符号 CRC 表，来自内核自带的 __ksymtab/__kcrctab
  2. vmlinux.btf            —— 原始 BTF，用于结构体布局比对
  3. layout_probe.c         —— 由 BTF 自动生成的 _Static_assert 探针

全部靠自动发现，不含任何写死的偏移，所以换内核版本后可直接复用。

用法:
    python refresh-kernel-abi.py <boot.img 或 kernel.bin> [输出目录]

输出目录默认是脚本所在目录下的 target/。
"""

import gzip
import io
import os
import re
import struct
import sys

IDENT = re.compile(rb'[A-Za-z_][A-Za-z0-9_.$]{0,159}\x00')
BTF_MAGIC = 0xEB9F


# --------------------------------------------------------------------------
# 1. 取出内核 Image
# --------------------------------------------------------------------------

def extract_kernel(blob):
    """从 boot.img 剥出内核载荷；已经是 Image 就原样返回。"""
    if blob[:8] == b'ANDROID!':
        kernel_size, = struct.unpack_from('<I', blob, 8)
        hdr_ver, = struct.unpack_from('<I', blob, 40)
        page = 4096 if hdr_ver >= 3 else struct.unpack_from('<I', blob, 36)[0]
        print('  Android boot header v%d, 内核载荷 %d 字节' % (hdr_ver, kernel_size))
        blob = blob[page:page + kernel_size]

    if blob[:2] == b'\x1f\x8b':
        print('  内核为 gzip 压缩，解压中')
        blob = gzip.decompress(blob)

    if blob[56:60] != b'ARM\x64':
        raise SystemExit('不是 ARM64 Image：+56 处魔数为 %r。'
                         '若为 lz4/zstd 压缩请先手动解压后再传入。' % blob[56:60])
    return blob


def kernel_release(d):
    """抓取 Linux banner 里的版本串。"""
    m = re.search(rb'Linux version ([0-9][^\s]*) ', d)
    return m.group(1).decode() if m else '(未找到 banner)'


# --------------------------------------------------------------------------
# 2. 自动定位 __ksymtab / __kcrctab / __ksymtab_strings
# --------------------------------------------------------------------------

def find_strings_region(d):
    """找 __ksymtab_strings。

    以 module_layout 为锚——每个开启 MODVERSIONS 的内核都导出它。真正位于
    字符串区的那一处，其前后应当是密集的 NUL 分隔标识符。
    """
    best = None
    for m in re.finditer(rb'module_layout\x00', d):
        o = m.start()
        if o == 0:
            continue
        lo = max(0, o - 2048)
        window = d[lo:o + 2048]
        # 标识符密度：可打印字符 + NUL 的占比
        good = sum(1 for c in window if c == 0 or 0x20 <= c < 0x7F)
        ratio = good / len(window)
        nuls = window.count(0)
        if ratio > 0.97 and nuls > 40:
            if best is None or ratio > best[1]:
                best = (o, ratio)
    if best is None:
        raise SystemExit('定位不到 __ksymtab_strings 中的 module_layout')
    return best[0]


def find_ksymtab(d, anchor_name_off, back=6 << 20):
    """在字符串区之前的窗口里，扫描 PREL32 的 kernel_symbol 数组。

    struct kernel_symbol（CONFIG_HAVE_ARCH_PREL32_RELOCATIONS，arm64 适用）:
        s32 value_offset; s32 name_offset; s32 namespace_offset;   // 12 字节
    name_offset 相对于该字段自身的地址。因为 Image 是平坦加载的，
    直接在文件偏移空间里做自相对运算即可，无需知道加载基址。
    """
    str_lo = anchor_name_off - (1 << 20)
    str_hi = anchor_name_off + (8 << 20)

    def nm(o):
        # 不要求前一字节是 NUL：__ksymtab_strings 带 SHF_MERGE|SHF_STRINGS，
        # 链接器会做尾部合并，符号名可以是另一个字符串的后缀。
        if not (str_lo <= o < str_hi) or o <= 0:
            return None
        m = IDENT.match(d, o)
        return m.group()[:-1].decode('ascii', 'replace') if m else None

    # 必须 4 字节对齐，否则扫描位置与真实条目错位，一条也匹配不上
    w_hi = anchor_name_off & ~3
    w_lo = max(0, w_hi - back) & ~3
    valid = bytearray(w_hi - w_lo)
    for e in range(w_lo, w_hi - 12, 4):
        v, = struct.unpack_from('<i', d, e + 4)
        if nm(e + 4 + v):
            valid[e - w_lo] = 1

    best = (0, 0, 0)
    e = w_lo
    while e < w_hi:
        if valid[e - w_lo]:
            k, c = e, 0
            while k < w_hi and valid[k - w_lo]:
                k += 12
                c += 1
            if c > best[2]:
                best = (e, k, c)
            e = k
        else:
            e += 4
    lo, hi, cnt = best
    if cnt < 500:
        raise SystemExit('__ksymtab 定位失败（只找到 %d 条）' % cnt)

    names = [nm(x + 4 + struct.unpack_from('<i', d, x + 4)[0])
             for x in range(lo, hi, 12)]

    # 字母序回退点 = __ksymtab_gpl 的起始索引（两张表各自有序）
    resets = [i for i in range(1, len(names)) if names[i] < names[i - 1]]
    if len(resets) != 1:
        print('  警告: 预期 1 个字母序回退点，实际 %d 个 %s'
              % (len(resets), resets[:5]))
    gpl_at = resets[0] if resets else len(names)

    # __kcrctab 紧随 __ksymtab_gpl，4 字节对齐；条目数必须与符号数一致
    crc_lo = (hi + 3) & ~3
    strings_start = min(x + 4 + struct.unpack_from('<i', d, x + 4)[0]
                        for x in range(lo, hi, 12))
    avail = (strings_start - crc_lo) // 4
    if avail != cnt:
        raise SystemExit('自校验失败: __kcrctab 可容纳 %d 个 u32，但有 %d 个符号。'
                         '边界判定有误，不要使用本次结果。' % (avail, cnt))

    print('  __ksymtab  0x%x..0x%x  %d 个符号（非 GPL %d，GPL %d）'
          % (lo, hi, cnt, gpl_at, cnt - gpl_at))
    print('  __kcrctab  0x%x  自校验通过（%d == %d）' % (crc_lo, avail, cnt))
    return names, crc_lo, gpl_at


def write_symvers(d, names, crc_lo, gpl_at, path):
    rows = []
    for i, n in enumerate(names):
        if not n:
            continue
        crc, = struct.unpack_from('<I', d, crc_lo + i * 4)
        kind = 'EXPORT_SYMBOL_GPL' if i >= gpl_at else 'EXPORT_SYMBOL'
        rows.append('0x%08x\t%s\tvmlinux\t%s\t' % (crc, n, kind))
    with open(path, 'w', newline='\n') as f:
        f.write('\n'.join(rows) + '\n')
    return len(rows)


# --------------------------------------------------------------------------
# 3. BTF 与布局断言
# --------------------------------------------------------------------------

def find_btf(d):
    """找到并校验内嵌的 BTF。"""
    for m in re.finditer(struct.pack('<H', BTF_MAGIC), d):
        o = m.start()
        if o + 24 > len(d) or d[o + 2] != 1:
            continue
        try:
            hdr_len, = struct.unpack_from('<I', d, o + 4)
            type_off, type_len, str_off, str_len = struct.unpack_from('<IIII', d, o + 8)
        except struct.error:
            continue
        if hdr_len != 24 or type_len == 0 or str_len == 0:
            continue
        if type_off != 0 or str_off != type_len:
            continue
        total = hdr_len + str_off + str_len
        if o + total <= len(d) and total > (1 << 20):
            return d[o:o + total]
    raise SystemExit('镜像中找不到有效 BTF')


def parse_btf(b):
    hdr_len, = struct.unpack_from('<I', b, 4)
    type_off, type_len, str_off, _ = struct.unpack_from('<IIII', b, 8)
    t0, s0 = hdr_len + type_off, hdr_len + str_off

    def s(o):
        return '' if o == 0 else b[s0 + o:b.index(b'\0', s0 + o)].decode('utf-8', 'replace')

    # 各 kind 记录尾部的可变长部分字节数（vlen 的倍数）
    tail = {6: 8, 19: 12, 13: 8, 15: 12, 14: 4, 17: 4, 1: 4, 3: 12}
    types, p = [], t0
    while p < t0 + type_len:
        name_off, info, size = struct.unpack_from('<III', b, p)
        vlen, kind, kflag = info & 0xFFFF, (info >> 24) & 0x1F, (info >> 31) & 1
        p += 12
        members = []
        if kind in (4, 5):
            for _ in range(vlen):
                mn, mt, mo = struct.unpack_from('<III', b, p)
                p += 12
                members.append((s(mn), mt, mo))
        elif kind in (3, 14, 17, 1):
            p += tail[kind]
        elif kind in tail:
            p += vlen * tail[kind]
        types.append((s(name_off), kind, size, members, kflag))
    return types


# 需要验证布局的结构体。None 表示断言全部非位域成员的偏移；
# 给出字段元组则只断言这几个（task_struct 有 200 多个成员，全断言噪音太大，
# 且其中不少随 config 变化，只盯模块真正解引用的即可）。
#
# 判据是"模块是否依赖该结构体的内存布局"：自己解引用字段的要验，
# 自己静态定义一份交给内核的更要验（内核会按它的布局来读）；
# 只是接过指针再原样传回内核的（seq_file、proc_dir_entry、file）不必验。
LAYOUT_TARGETS = (
    ('sock_common', None),          # eligible() 读 sk_family
    ('sock', None),                 # eligible() 读 sk_kern_sock
    ('task_struct', (
        'pid', 'tgid',              # task_tgid_nr()
        'cred', 'real_cred',        # current_uid() 经 current->cred
        'group_leader',             # 取线程组组长的启动时间
        'start_boottime',
        'comm',                     # get_task_comm()
        # CONFIG_STACKPROTECTOR_PER_TASK + CC_HAVE_STACKPROTECTOR_SYSREG 下，
        # arm64 的栈金丝雀通过 sp_el0 + offsetof(task_struct, stack_canary)
        # 访问，偏移是编译期常量。构建树与真机对不上时，每个受保护函数都会从
        # 错误位置读金丝雀——自洽所以未必立刻崩，但那是在越界读 task_struct，
        # 必须钉死。
        'stack_canary',
    )),
    ('cred', ('uid', 'euid', 'fsuid')),   # current_uid() 最终读的就是 cred.uid
    ('file_operations', None),      # 模块静态定义 probe_fops
    ('miscdevice', None),           # 模块静态定义 probe_device
)


# 模块直接读取的位域。offsetof 表达不了它们，所以改为在模块加载时自检：
# 把归零结构体里的该位置 1，确认它落在真机 BTF 指明的字节与位上。
#
# 这是必须的，不是补充：位域在同一存储单元内调换顺序，既不改变前后非位域成员
# 的偏移，也不改变结构体大小，因此 layout_probe.c 里的断言一个都不会失败，
# 而模块会读到错误的位。
BITFIELD_TARGETS = (
    ('sock', 'sk_kern_sock'),       # eligible() 用它排除内核 socket
)


def write_bitfield_header(types, path, targets=BITFIELD_TARGETS):
    """把位域的字节与位位置写成宏，供模块加载时自检。"""
    def find(nm):
        for t in types:
            if t[0] == nm and t[1] == 4:
                return t
        return None

    lines = ['/* 由 refresh-kernel-abi.py 从真机 BTF 自动生成，请勿手工编辑 */',
             '#ifndef SBO_BITFIELDS_H',
             '#define SBO_BITFIELDS_H',
             '']
    for sname, fname in targets:
        t = find(sname)
        if not t:
            raise SystemExit('真机 BTF 里找不到 struct %s' % sname)
        _, _, _size, members, kflag = t
        if not kflag:
            raise SystemExit('struct %s 的 BTF 未标记位域信息，无法定位 %s'
                             % (sname, fname))
        for mn, _mt, mo in members:
            if mn != fname:
                continue
            bitsz = (mo >> 24) & 0xFF
            bit = mo & 0xFFFFFF
            if bitsz != 1:
                raise SystemExit('%s.%s 位宽为 %d，本自检只支持单比特位域'
                                 % (sname, fname, bitsz))
            macro = ('SBO_' + sname + '_' + fname).upper()
            lines.append('/* %s.%s: 位偏移 %d（字节 %d，字节内第 %d 位），位宽 %d */'
                         % (sname, fname, bit, bit // 8, bit % 8, bitsz))
            lines.append('#define %s_BYTE %d' % (macro, bit // 8))
            lines.append('#define %s_BIT  %d' % (macro, bit % 8))
            lines.append('')
            break
        else:
            raise SystemExit('struct %s 中找不到位域 %s' % (sname, fname))
    lines += ['#endif /* SBO_BITFIELDS_H */', '']
    with open(path, 'w', newline='\n') as f:
        f.write('\n'.join(lines))
    return len(targets)


def write_layout_probe(types, path, targets=LAYOUT_TARGETS):
    """为模块实际依赖布局的结构体生成 _Static_assert。"""
    def find(nm):
        for t in types:
            if t[0] == nm and t[1] == 4:
                return t
        return None

    lines = ['/* 由 refresh-kernel-abi.py 从真机 BTF 自动生成，请勿手工编辑 */',
             '#include <linux/sched.h>',
             '#include <linux/cred.h>',
             '#include <linux/fs.h>',
             '#include <linux/miscdevice.h>',
             '#include <linux/stddef.h>',
             '#include <linux/module.h>',
             '#include <net/sock.h>',
             '']
    n = 0
    for sname, only in targets:
        t = find(sname)
        if not t:
            # 不能只写条注释continue：那会静默少掉一整个结构体的断言，
            # 于是"校验通过"却仍按错误偏移访问内存——正是本方案最该避免的失败。
            raise SystemExit(
                '真机 BTF 里找不到 struct %s。缺少关键布局时必须失败，'
                '不能继续生成不完整的断言。' % sname)
        _, _, size, members, kflag = t
        available = {name for name, _mt, _mo in members if name}
        if only:
            absent = [name for name in only if name not in available]
            if absent:
                raise SystemExit(
                    'struct %s 中找不到字段 %s。模块会直接解引用它们，'
                    '断言缺失意味着这些偏移没被校验过。'
                    % (sname, ', '.join(absent)))
        lines.append('_Static_assert(sizeof(struct %s) == %d, "size %s");'
                     % (sname, size, sname))
        n += 1
        for mn, _mt, mo in members:
            if only is not None and mn not in only:
                continue
            bitsz = (mo >> 24) & 0xFF if kflag else 0
            bit = (mo & 0xFFFFFF) if kflag else mo
            if not mn or bitsz or bit % 8:
                # 匿名成员和位域无法用 __builtin_offsetof 表达。
                #
                # 模块确实读了一个位域（sock.sk_kern_sock），它没有直接断言，
                # 而是被前后夹住：结构体总长被断言，位域所在字节前后的非位域
                # 成员偏移也都被断言（例如 sk_shutdown 紧跟其后）。位域组的
                # 存储位置因此没有活动余地。这不如直接断言，但是 C 语言能做到
                # 的上限；改动这一带的字段时要意识到这层保护是间接的。
                continue
            lines.append('_Static_assert(__builtin_offsetof(struct %s, %s) == %d, '
                         '"off %s.%s");' % (sname, mn, bit // 8, sname, mn))
            n += 1
    lines += ['', 'MODULE_LICENSE("GPL");', '']
    with open(path, 'w', newline='\n') as f:
        f.write('\n'.join(lines))
    return n


# --------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    src = sys.argv[1]
    here = os.path.dirname(os.path.abspath(__file__))
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(here, 'target')
    os.makedirs(out, exist_ok=True)

    print('读取 %s' % src)
    d = extract_kernel(open(src, 'rb').read())
    print('  内核 Image %d 字节' % len(d))
    release = kernel_release(d)
    print('  版本串: %s' % release)

    # 版本串单独落盘：Magisk 包用它做开机前的内核比对。带 CRC 的模块在
    # same_magic() 里会跳过 vermagic 的版本号部分，所以内核换代时 insmod
    # 未必拦得住，需要这一道显式检查。
    p_release = os.path.join(out, 'kernel-release')
    with open(p_release, 'w', newline='\n') as f:
        f.write(release + '\n')

    print('定位符号表')
    anchor = find_strings_region(d)
    names, crc_lo, gpl_at = find_ksymtab(d, anchor)

    p_sym = os.path.join(out, 'Module.symvers.device')
    cnt = write_symvers(d, names, crc_lo, gpl_at, p_sym)
    print('  -> %s  (%d 行)' % (p_sym, cnt))

    print('提取 BTF')
    btf = find_btf(d)
    p_btf = os.path.join(out, 'vmlinux.btf')
    open(p_btf, 'wb').write(btf)
    print('  -> %s  (%d 字节)' % (p_btf, len(btf)))

    types = parse_btf(btf)
    p_probe = os.path.join(here, 'layout_probe.c')
    n = write_layout_probe(types, p_probe)
    print('  %d 个 BTF 类型 -> %s  (%d 条断言)' % (len(types), p_probe, n))

    p_bits = os.path.join(here, 'sbo_bitfields.h')
    m = write_bitfield_header(types, p_bits)
    print('  -> %s  (%d 个位域，由模块加载时自检)' % (p_bits, m))

    print('\n完成。下一步:')
    print('  1. 把 Module.symvers.device 拷到内核构建目录作为 Module.symvers')
    print('  2. 用 layout_probe.c 编一个模块验证结构体布局（编译通过即全部一致）')
    print('  3. 重编 sb_sockowner_probe 并核对 CRC，再手动 insmod')


if __name__ == '__main__':
    main()
