# -*- coding: utf-8 -*-
"""核对一个 .ko 的符号 CRC 是否与目标内核一致。

被 rebuild-and-verify.sh 和 pack.sh 共用，避免两处各写一份校验逻辑而慢慢漂移。

为什么这道检查值得单独存在：模块的版本表里每个导入符号都带一个 CRC，内核加载
时逐个比对，不符就拒绝。这道保险正是安全的来源——IPSET_LKM 的加载器靠改写符号
绕过了它，结果内核一升级就 bootloop。所以打包前必须确认这些 CRC 确实来自目标
内核，而不是别处。

## 两张版本表，以及为什么两张都要查

开了 CONFIG_EXTENDED_MODVERSIONS 的内核会生成两套版本信息：

  __versions                        传统格式，每条 8 字节 CRC + 56 字节符号名
  __version_ext_crcs / _ext_names   扩展格式，u32 数组 + NUL 分隔的名字

而 kernel/module/version.c 的 check_version() 里写着：

    /* If we have extended version info, rely on it */
    if (info->index.vers_ext_crc) { ... return 1; }

扩展段存在时，传统段被**完全忽略**。所以只查 __versions 等于查了一张内核根本
不看的表。反过来，为不带扩展段的内核构建时又只有传统段。两张都查，并且要求
它们彼此一致，才是安全的做法。

还要注意扩展段的一个语义：某个符号在扩展表里查不到时，内核只 pr_warn_once
然后**放行**。所以"表里缺符号"不会被内核拦住，只能在这里拦。

用法:
    python verify-ko.py <module.ko> <Module.symvers>

任何一项不过都以非零状态退出。
"""

import struct
import sys

EM_AARCH64 = 183
VERSIONS_ENTRY_SIZE = 64        # struct modversion_info: u64 crc + char[56]
VERSIONS_NAME_SIZE = 56

# 每个模块都必然导入它；缺了说明这张表不完整或根本不是版本表。
REQUIRED_SYMBOL = 'module_layout'


class Rejected(Exception):
    pass


def read_elf(path):
    """读出 ELF 的节表，顺便确认架构。"""
    blob = open(path, 'rb').read()
    if blob[:4] != b'\x7fELF':
        raise Rejected('%s 不是 ELF 文件' % path)
    machine, = struct.unpack_from('<H', blob, 0x12)
    if machine != EM_AARCH64:
        raise Rejected('架构不是 AArch64（e_machine=%d）' % machine)

    section_offset, = struct.unpack_from('<Q', blob, 0x28)
    entry_size, count, name_index = struct.unpack_from('<HHH', blob, 0x3A)

    def header(index):
        base = section_offset + index * entry_size
        return struct.unpack_from('<IIQQQQ', blob, base)

    name_table = header(name_index)[4]
    sections = {}
    for index in range(count):
        name_offset, _type, _flags, _addr, offset, size = header(index)
        start = name_table + name_offset
        name = blob[start:blob.index(b'\0', start)].decode()
        sections[name] = (offset, size)
    return blob, sections


def parse_classic(blob, sections):
    """__versions：每条 8 字节 CRC + 56 字节符号名。"""
    if '__versions' not in sections:
        return None
    offset, size = sections['__versions']
    if size == 0:
        return {}
    if size % VERSIONS_ENTRY_SIZE:
        raise Rejected('__versions 长度 %d 不是 %d 的整数倍，格式不符'
                       % (size, VERSIONS_ENTRY_SIZE))
    table = {}
    for position in range(offset, offset + size, VERSIONS_ENTRY_SIZE):
        crc, = struct.unpack_from('<Q', blob, position)
        raw = blob[position + 8:position + VERSIONS_ENTRY_SIZE]
        name = raw.split(b'\0')[0].decode('ascii', 'replace')
        if not name:
            raise Rejected('__versions 中存在空符号名')
        table[name] = crc & 0xFFFFFFFF
    return table


def undefined_symbols(blob, sections):
    """列出 ELF 的未定义符号，即模块要从内核解析的全部导入。

    版本表里只要有一个导入符号缺席，内核加载时对它就不做 CRC 校验——扩展表
    路径甚至只 pr_warn_once 就放行。所以必须拿这份清单去核对版本表的完整性，
    只检查 module_layout 存在是不够的。
    """
    if '.symtab' not in sections or '.strtab' not in sections:
        raise Rejected('模块缺少 .symtab/.strtab，无法核对导入符号完整性')
    sym_offset, sym_size = sections['.symtab']
    str_offset, _str_size = sections['.strtab']
    if sym_size % 24:
        raise Rejected('.symtab 长度 %d 不是 Elf64_Sym(24) 的整数倍' % sym_size)

    names = set()
    for position in range(sym_offset, sym_offset + sym_size, 24):
        name_offset, _info, _other, shndx = struct.unpack_from('<IBBH', blob, position)
        if shndx != 0 or name_offset == 0:   # SHN_UNDEF 之外的一概跳过
            continue
        start = str_offset + name_offset
        name = blob[start:blob.index(b'\0', start)].decode('ascii', 'replace')
        if name:
            names.add(name)
    return names


def parse_extended(blob, sections):
    """__version_ext_crcs 是 u32 数组，__version_ext_names 是同序的 NUL 分隔名字。"""
    has_crcs = '__version_ext_crcs' in sections
    has_names = '__version_ext_names' in sections
    if has_crcs != has_names:
        # 内核的 modversion_ext_start() 在只有一半时会把 remaining 置零，于是
        # 整张扩展表被当作空表，而 check_version() 一旦看到 vers_ext_crc 就不再
        # 回退到 __versions——结果是所有符号都不做校验。必须直接拒绝。
        raise Rejected('扩展版本表只存在一半（crcs=%s, names=%s），'
                       '这会让内核跳过全部 CRC 校验' % (has_crcs, has_names))
    if not has_crcs:
        return None
    crc_offset, crc_size = sections['__version_ext_crcs']
    name_offset, name_size = sections['__version_ext_names']
    if crc_size == 0:
        # 必须区分"段不存在"和"段存在但为空"。
        #
        # check_version() 判断的是 if (info->index.vers_ext_crc)——节索引是否
        # 存在，而不是长度。段存在但长度为零时，内核照样走扩展路径、迭代零个
        # 条目、pr_warn_once 然后 return 1，结果是**所有符号一个都不校验**，
        # 而且不会回退到 __versions。
        #
        # 所以这种模块比完全没有版本表更危险：看起来两张表齐全，实际一张也不
        # 生效。绝不能因为传统表完整就放行。
        raise Rejected('扩展版本表存在但为空。内核会优先采用它并跳过全部 CRC '
                       '校验，且不会回退到 __versions')
    if crc_size % 4:
        raise Rejected('__version_ext_crcs 长度 %d 不是 4 的整数倍' % crc_size)

    count = crc_size // 4
    names = blob[name_offset:name_offset + name_size].split(b'\0')
    names = [item.decode('ascii', 'replace') for item in names if item]
    if len(names) != count:
        raise Rejected('扩展版本表不自洽：%d 个 CRC 对 %d 个名字'
                       % (count, len(names)))
    table = {}
    for index in range(count):
        crc, = struct.unpack_from('<I', blob, crc_offset + index * 4)
        table[names[index]] = crc
    return table


def kernel_versions(path):
    """读 Module.symvers：CRC \t 符号 \t 模块 \t 导出类型。"""
    table = {}
    with open(path) as handle:
        for line in handle:
            fields = line.rstrip('\n').split('\t')
            if len(fields) >= 2:
                table[fields[1]] = int(fields[0], 16)
    if not table:
        raise Rejected('%s 里没有任何符号' % path)
    return table


def compare(label, ours, theirs):
    mismatched = [(name, crc, theirs.get(name))
                  for name, crc in sorted(ours.items())
                  if theirs.get(name) != crc]
    for name, crc, expected in mismatched:
        print('   MISMATCH [%s] %-36s 模块 0x%08x  内核 %s'
              % (label, name, crc, '(不存在)' if expected is None else '0x%08x' % expected))
    print('   %-8s %d 个符号，一致 %d，不一致 %d'
          % (label, len(ours), len(ours) - len(mismatched), len(mismatched)))
    return len(mismatched)


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    try:
        blob, sections = read_elf(sys.argv[1])
        classic = parse_classic(blob, sections)
        extended = parse_extended(blob, sections)

        present = {name: table for name, table in
                   (('__versions', classic), ('扩展版本表', extended))
                   if table}
        if not present:
            raise Rejected(
                '模块里没有任何非空的版本表。\n'
                '   这正是 IPSET_LKM 那类强制加载模块的形态：内核无从校验，\n'
                '   只能靠 vermagic 逐字匹配，换内核就会以最危险的方式失败。')

        theirs = kernel_versions(sys.argv[2])

        # 两张表都在时必须彼此一致，否则无法判断内核会按哪张执行。
        if classic and extended and classic != extended:
            only_classic = set(classic) - set(extended)
            only_extended = set(extended) - set(classic)
            raise Rejected(
                '两张版本表内容不一致，无法确定内核会采用哪张。\n'
                '   仅在 __versions 中: %s\n'
                '   仅在扩展表中: %s'
                % (sorted(only_classic) or '无', sorted(only_extended) or '无'))

        imports = undefined_symbols(blob, sections)

        failures = 0
        for label, table in present.items():
            if REQUIRED_SYMBOL not in table:
                raise Rejected('%s 中缺少 %s，该表不完整' % (label, REQUIRED_SYMBOL))
            # 每个导入符号都必须有 CRC。缺席的符号内核不会校验，等于在一张
            # 看似通过的表上开了个口子。
            uncovered = sorted(imports - set(table))
            if uncovered:
                raise Rejected(
                    '%s 未覆盖以下导入符号，它们加载时不会被校验：\n   %s'
                    % (label, ', '.join(uncovered)))
            failures += compare(label, table, theirs)
        print('   导入符号 %d 个，全部有 CRC' % len(imports))

        if '扩展版本表' in present:
            print('   注意：本内核 check_version() 优先采用扩展表，'
                  '__versions 会被忽略')
        return 1 if failures else 0

    except Rejected as reason:
        print('   拒绝：%s' % reason)
        return 1


if __name__ == '__main__':
    sys.exit(main())
