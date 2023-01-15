// Tool for parsing the SYM files found inside RE4 GC debug build into IDA/Ghidra compatible naming-scripts

#include <iostream>
#include <cstdio>
#include <vector>
#include <string>
#include <algorithm>
#include <fstream>
#include <filesystem>

struct SymHeader
{
    uint32_t num_funcs;
    uint32_t funcinfo_addr;
    uint32_t strtab_addr;
    uint32_t funcname_addr;
};

struct SymFuncInfo // funcinfo
{
    uint32_t virtual_addr;
    uint32_t unk4;
    uint32_t unk8;
    uint32_t name_addr;
};

struct SymFuncInfo_Parsed // funcinfo
{
    uint32_t virtual_addr;
    std::string name;
    uint32_t unk4;
    uint32_t unk8;
};

std::string ReplaceAll(std::string str, const std::string& from, const std::string& to) {
    size_t start_pos = 0;
    while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); // Handles case where 'to' is a substring of 'from'
    }
    return str;
}

uint32_t baseAddress = 0;
bool baseAddressSet = false;

int main(int argc, char* argv[])
{
    if (argc <= 1)
    {
        std::cout << "Usage: re4sym <path/to/sym/file> [0xBaseAddress]\n";
        std::cout << "Will create filepath.ida.py, filepath.ghidra.txt & filename.dolphin.map files containing symbol names/addresses\n";
        std::cout << "baseAddress can optionally be specified, to be added to all addrs inside the exported symbols\n";
        return 1;
    }

    if (argc >= 3)
    {
        try
        {
            baseAddress = std::stoul(argv[2], 0, 0);
            baseAddressSet = true;
            std::cout << "Base address set to 0x" << std::hex << baseAddress << "\n";
        }
        catch (...)
        {
            baseAddress = 0;
            std::cout << "Invalid base address specified, using default.\n";
        }
    }

    FILE* file;
    fopen_s(&file, argv[1], "rb");
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    auto mem = std::make_unique<uint8_t[]>(size);
    if (!mem)
        return 0;
    fread(mem.get(), 1, size, file);
    fclose(file);

    SymHeader* header = (SymHeader*)mem.get();
    header->num_funcs = _byteswap_ulong(header->num_funcs);
    header->funcinfo_addr = _byteswap_ulong(header->funcinfo_addr);
    header->strtab_addr = _byteswap_ulong(header->strtab_addr);
    header->funcname_addr = _byteswap_ulong(header->funcname_addr);

    std::vector<std::string> funcnames;

    uint32_t* funcname_addr = (uint32_t*)(mem.get() + 0x10);
    uint32_t* funcname_end = (uint32_t*)(mem.get() + header->funcinfo_addr);
    while (funcname_end > funcname_addr)
    {
        uint32_t cur_addr = _byteswap_ulong(*funcname_addr);
        char* cur_str = (char*)(mem.get() + header->strtab_addr + cur_addr);
        funcnames.push_back(cur_str);
        funcname_addr++;
    }

    std::vector<SymFuncInfo_Parsed> funcinfos;
    SymFuncInfo* cfuncinfos = (SymFuncInfo*)(mem.get() + header->funcinfo_addr);
    for (uint32_t i = 0; i < header->num_funcs; i++)
    {
        auto info = &cfuncinfos[i];

        SymFuncInfo_Parsed parsed;
        parsed.virtual_addr = _byteswap_ulong(info->virtual_addr);

        char* name = (char*)(mem.get() + header->funcname_addr + _byteswap_ulong(info->name_addr));
        parsed.name = name;

        parsed.unk4 = _byteswap_ulong(info->unk4);
        parsed.unk8 = _byteswap_ulong(info->unk8);

        funcinfos.push_back(parsed);
    }


    std::filesystem::path input = argv[1];
    std::filesystem::path basedir = input.parent_path();
    auto ida_path = basedir / input.filename().replace_extension(".ida.py");
    auto ghidra_path = basedir / input.filename().replace_extension(".ghidra.txt");
    auto dolphin_path = basedir / input.filename().replace_extension(".dolphin.map");

    bool isDolFile = input.filename().extension() == ".dol";

    std::ofstream ida(ida_path, std::ofstream::out | std::ofstream::trunc);
    std::ofstream ghidra(ghidra_path, std::ofstream::out | std::ofstream::trunc);
    std::ofstream dolphin(dolphin_path, std::ofstream::out | std::ofstream::trunc);

    if (ida.is_open())
    {
        // IDA boilerplate to handle dupe names & create code for functions
        ida << "import ida_segment\n";
        ida << "\n";
        ida << "def namer(ea, name):\n";
        ida << "    origName = name\n";
        ida << "    existEA = get_name_ea(idaapi.BADADDR, name)\n";
        ida << "    i = 0\n";
        ida << "    while existEA != idaapi.BADADDR:\n";
        ida << "        name = origName + \"_\" + str(i)\n";
        ida << "        i = i + 1\n";
        ida << "        existEA = get_name_ea(0, name)\n";
        ida << "\n";
        ida << "    set_name(ea, name)\n";
        ida << "    seg = ida_segment.getseg(ea)\n";
        ida << "    seg_name = ida_segment.get_segm_name(seg)\n";
        ida << "    if seg_name.startswith(\".text\"):\n";
        ida << "        idc.add_func(ea)\n";
        ida << "\n";
    }

    // dolphin map boilerplate
    if (dolphin.is_open())
        dolphin << ".text section layout\n";

    std::vector<std::string> existNames;
    for (auto& info : funcinfos)
    {
        auto s = ReplaceAll(info.name, " virtual table", "_vtable");

        std::replace(s.begin(), s.end(), '<', '_');
        std::replace(s.begin(), s.end(), '>', '_');
        std::replace(s.begin(), s.end(), ' ', '_');

        if (s.length() <= 1)
            continue;

        if (s[0] == '@')
            continue;

        if (s.length() >= 4 && s.substr(0, 4) == "sub_")
            s = "_" + s;

        auto s_orig = s;
        int dupeCount = 0;
        while (std::find(existNames.begin(), existNames.end(), s) != existNames.end())
            s = s_orig + "_" + std::to_string(dupeCount++);

        existNames.push_back(s);

        uint32_t ida_addr = info.virtual_addr;
        uint32_t ghidra_addr = info.virtual_addr;

        if (baseAddressSet)
        {
            // remove main exe base addr if present...
            if (ida_addr >= 0x80000000)
                ida_addr = ghidra_addr = (ida_addr - 0x80000000);

            ida_addr += baseAddress;
            ghidra_addr += baseAddress;
        }
        else
        {
            // Base addr not specified, but module isn't at valid address (0x80000000 or beyond)
            // Add standard base addrs used by IDA & Ghidra
            if (ida_addr < 0x80000000)
            {
                // default ida/ghidra load addrs
                ida_addr += 0x80500000u;
                ghidra_addr += 0x80000000u;
            }
        }

        if (ida.is_open())
            ida << "namer(0x" << std::hex << ida_addr << ", \"" << s << "\")\n";
        if (ghidra.is_open())
            ghidra << s << " 0x" << std::hex << ghidra_addr << "\n";
        if (dolphin.is_open())
            dolphin << std::hex << ida_addr << " " << s << "\n"; // 2 column dolphin map
        //printf("set_name(0x%X,\"%s\")\n", info.virtual_addr, s.c_str(), info.unk4, info.unk8);
    }

    if (ida.is_open())
        std::cout << "Wrote IDAPython script to " << ida_path << std::endl;
    else
        std::cout << "Failed to write IDAPython script to " << ida_path << std::endl;

    if (ghidra.is_open())
        std::cout << "Wrote Ghidra ImportSymbolsScript file to " << ghidra_path << std::endl;
    else
        std::cout << "Failed to write Ghidra ImportSymbolsScript file to " << ghidra_path << std::endl;

    if (dolphin.is_open())
        std::cout << "Wrote Dolphin MAP file to " << dolphin_path << std::endl;
    else
        std::cout << "Failed to write Dolphin MAP file to " << dolphin_path << std::endl;
}
