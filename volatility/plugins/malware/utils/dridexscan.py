# Detecting Dridex for Volatility

import volatility.plugins.taskmods as taskmods
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug
import volatility.plugins.malware.malfind as malfind
import re
import pefile
from struct import unpack, unpack_from
from collections import OrderedDict
from Crypto.Cipher import ARC4

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

dridex_sig = {
    'namespace1' : 'rule Dridex { \
                      meta: \
                        description = "detect Dridex in memory" \
                        author = "Bruno Humic" \
                        rule_usage = "memory scan" \
                        reference = "internal research" \
                      strings: \
                        $ep = { 55 8B EC 51 56 6A ?? 8D 4D ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? [10-15] 74 ?? 83 7D 0C 01 8B 75 ?? 89 35 ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 80 3D ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 74} \
                        $get_ip = { 55 8B EC A1 ?? ?? ?? ?? 83 EC ?? (53 33 DB 3B C3 | 85 C0) 0F 85 ?? 00 00 00 6A ?? E8 ?? ?? ?? ?? 83 C4 ?? [2] 74 1? (89 58 04 89 58 08 89 58 0C | C7 40 04 00 00 00 00 C7 40 08 00 00 00 00 C7 40 0C 00 00 00 00) [0-5] EB 0? (89 1D ?? ?? ?? ?? | 33 C0) (66 A1 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? 0F B7 C8 89 0A A0 ?? ?? ?? ?? 3C ?? | 0F B7 ?? ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? 89 08 80 3D ?? ?? ?? ?? ??) 77 0? (8A 0D | A0) ?? ?? ?? ?? [0-6] 57 33 FF (84 D2 | 80 3D ?? ?? ?? ?? ??) 7? 5? 56 BE ?? ?? ?? ?? [2] 00 66 8B 46 04 [5] 8? ?5 ?? 8? ?? ?? [0-4] 66 89 4? ?? 8? ?D ?? [0-8] E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? [2-5] 83 C1 ?? (52 50 | FF 31 FF 32) E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? (8A 0D ?? ?? ?? ?? 0F B6 D1 47 83 C6 ?? | 0F B6 ?? ?? ?? ?? ?? 8D 76 ?? 47) 3B F? 7C B? 5E A1 ?? ?? ?? ?? 5F [0-1] 8B E5 5D C3 } \
                        $get_rc4key = { 6A ?? 8D [2-5] [0-1] BA ?? ?? ?? ?? [0-1] 8D [2-5] E8 ?? ?? ?? ?? 8B C8 E8 ?? ?? ?? ?? 8D [2-5] E8 ?? ?? ?? ?? 8? [1-2] E8 ?? ?? ?? ?? 50 8D [2-5] E8 ?? ?? ?? ?? 8B [2-5] BA FF FF FF 7F E8 ?? ?? ?? ?? 8B [2-5] [0-6] (53 53 53 | 6A 00 6A 00 6A 00) [0-6] 8B F? E8 ?? ?? ?? ?? 50 8? [1-2] E8 ?? ?? ?? ?? 50 (53 | 6A 00) 8? [1-2] E8 ?? ?? ?? ?? 50 8B D? 8B C? E8 } \
                      condition: all of them }'
}

# Specific config offsets for accessing the C2 config values
# for various versions
# Common offsets:
# Offset to the instruction relative to the start of the matched string
botnetid_instr_offset = 0x3A
# Version 1: example d0fe656e8ecd46161ee2fced73c00fb41de128174cac80c51b9a1357c3b6868
config_offsets_v1 = { 
    # Offset to the address part relative to the start of instruction
    "botnetid_addr_offset" : 0x02, 
    # Offset to the instruction relative to the start of the matched string
    "c2_instr_offset" : 0x4B,
    # Offset to the address part relative to the start of instruction
    "c2_addr_offset" : 0x01
}

# Version 2: example fcc0db0ce710f68915b4d73274d69bb5765012b02631bb737c66a32a9a708aab
config_offsets_v2 = {
    # Offset to the address part relative to the start of instruction
    "botnetid_addr_offset" : 0x03, 
    # Offset to the instruction relative to the start of the matched string
    "c2_instr_offset" : 0x4D,
    # Offset to the address part relative to the start of instruction
    "c2_addr_offset" : 0x02
}

class dridexConfig(taskmods.DllList):
    """Detect processes infected with redleaves malware"""

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows'), profile.metadata.get('memory_model', '32bit')

    def get_vad_base(self, task, address):
        for vad in task.VadRoot.traverse():
            if address >= vad.Start and address < vad.End:
                return vad.Start, vad.End
        return None

    def parse_config(self, module_snapshot, botnetid_rva, c2list_rva, cryptkey_config_rva):

        p_data = OrderedDict()

        p_data["BotnetID"] = unpack_from("<H", module_snapshot, botnetid_rva)[0]

        # TODO: c2_count_offset should become an argument
        c2_count = unpack_from("<B", module_snapshot, c2list_rva)[0]
        for i in range(c2_count):
            offset = c2list_rva + 1 + i * 0x06
            a = unpack_from("<B", module_snapshot, offset)[0]
            b = unpack_from("<B", module_snapshot, offset + 1)[0]
            c = unpack_from("<B", module_snapshot, offset + 2)[0]
            d = unpack_from("<B", module_snapshot, offset + 3)[0]
            port = unpack_from("<H", module_snapshot, offset + 4)[0]
            p_data["Server" + str(i + 1)] = "{0}.{1}.{2}.{3}:{4}".format(a, b, c, d, port)

        encrypted_size = 0
        for b in module_snapshot[cryptkey_config_rva:]:
            if ord(b) == 0:
                break
            encrypted_size = encrypted_size + 1

        encrypted_size = encrypted_size * 2
        cryptkey_config_blob = module_snapshot[cryptkey_config_rva : cryptkey_config_rva + encrypted_size]
        key = cryptkey_config_blob[:0x28][::-1]
        encrypted = cryptkey_config_blob[0x28:]

        cipher = ARC4.new(key)
        decrypted = cipher.encrypt(encrypted)
        p_data["Decrypted blob"] = decrypted

        for part in decrypted.split(chr(0x00)):
            if ";" in part:
                p_data["Encryption key RC4"] = part.split(";")[0]

        return p_data

    def calculate(self):

        if not has_yara:
            debug.error("Yara must be installed for this plugin")

        addr_space = utils.load_as(self._config)

        os, memory_model = self.is_valid_profile(addr_space.profile)
        if not os:
            debug.error("This command does not support the selected profile.")

        rules = yara.compile(sources=dridex_sig)

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            scanner = malfind.VadYaraScanner(task=task, rules=rules)

            for hit, address in scanner.scan():
                vad_base_addr, end = self.get_vad_base(task, address)
                proc_addr_space = task.get_process_address_space()
                # Contains entire VAD
                data = proc_addr_space.zread(vad_base_addr, end - vad_base_addr)

                config_data = []
                
                module_offset_start_in_vad = 0
                module_base = 0
                module_snapshot = 0
                module_found = False

                botnetid_addr = 0
                botnetid_rva  = 0
                c2list_addr = 0
                c2list_rva  = 0
                config_found = False

                cryptkey_config_rva = 0
                cryptkey_layer2_offset = 0
                cryptkey_layer2_found = False

                for moffset, mid, mdata in hit.strings:
                    if mid == '$ep':
                        for module in task.get_load_modules():
                            if address >= module.DllBase and address < module.DllBase + module.SizeOfImage:
                                module_offset_start_in_vad = module.DllBase - vad_base_addr
                                module_offset_end_in_vad = module_offset_start_in_vad + module.SizeOfImage
                                module_base = module.DllBase
                                module_size = module.SizeOfImage
                                module_snapshot = data[module_offset_start_in_vad : module_offset_end_in_vad]
                                module_found = True
                                break
                    elif mid == '$get_ip':
                        # Get opcode for MOV instruction to determine version
                        config_offsets = 0
                        mov_instr = unpack_from(">H", mdata, botnetid_instr_offset)[0]
                        if mov_instr == 0x66A1:
                            config_offsets = config_offsets_v1
                        elif mov_instr == 0x0FB7:
                            config_offsets = config_offsets_v2
                        botnetid_addr = unpack_from("<I", mdata, botnetid_instr_offset + config_offsets["botnetid_addr_offset"])[0]
                        c2list_addr = unpack_from("<I", mdata, config_offsets["c2_instr_offset"] + config_offsets["c2_addr_offset"])[0]
                        config_found = True
                    elif mid == '$get_rc4key':
                        offset = 0
                        for b in mdata:
                            if ord(b) == 0xE8:
                                break
                            offset = offset + 1
                        cryptkey_layer2_offset = unpack_from("<I", mdata, offset + 1)[0] + moffset + offset + 5
                        cryptkey_layer2_found = True

                if module_found and config_found and cryptkey_layer2_found:
                    botnetid_rva = botnetid_addr - module_base
                    c2list_rva = c2list_addr - module_base
                    cryptkey_layer2_rva = cryptkey_layer2_offset - module_offset_start_in_vad
                    cryptkey_config_addr = unpack_from("<I", module_snapshot, cryptkey_layer2_rva + 5)[0]
                    cryptkey_config_rva = cryptkey_config_addr - module_base

                if module_found and config_found and cryptkey_layer2_found:
                    config_data.append(self.parse_config(module_snapshot, botnetid_rva, c2list_rva, cryptkey_config_rva))
                    yield task, vad_base_addr, end, hit, memory_model, config_data
                    break

    def render_text(self, outfd, data):

        delim = '-' * 70

        for task, vad_start, vad_end, malname, memory_model, config_data in data:
            outfd.write("{0}\n".format(delim))
            outfd.write("Process: {0} ({1})\n\n".format(task.ImageFileName, task.UniqueProcessId))

            outfd.write("[Download Config Info]\n")
            for p_data in config_data:
                for id, param in p_data.items():
                    outfd.write("{0:<4}: {1}\n".format(id, param))