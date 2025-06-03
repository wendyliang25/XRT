#!/usr/bin/env python3

import datetime
import subprocess
import os
import re
import shutil
import sys

import parse_cpp_func_args

def is_windows():
    if os.name == 'nt':
        return True
    else:
        return False

def get_class_header(decl: str):
    headers = set()
    headers.add("xrt.h")
    if re.search(r'xrt::ext::bo|xrt::bo', decl):
        headers.add("xrt/xrt_bo.h")
    if re.search(r'xrt::aie|xrt::elf', decl):
        headers.add("xrt/xrt_aie.h")
    if re.search(r'xrt::device', decl):
        headers.add("xrt/xrt_device.h")
    if re.search(r'xrt::xclbin', decl):
        headers.add("xrt/xrt_device.h")
    if re.search(r'xrt::xclbin_repository', decl):
        headers.add("xrt/xrt_device.h")
    if re.search(r'xrt::ip[:\s),&*]', decl):
        headers.add("xrt/experimental/xrt_ip.h")
    if re.search(r'xrt::kernel', decl):
        headers.add("xrt/xrt_kernel.h")
    if re.search(r'xrt::fence', decl):
        headers.add("xrt/xrt_kernel.h")
    if re.search(r'xrt::run', decl):
        headers.add("xrt/xrt_kernel.h")
    if re.search(r'xrt::hw_context', decl):
        headers.add("xrt/xrt_hw_context.h")
    if re.search(r'xrt::uuid', decl):
        headers.add("xrt/xrt_uuid.h")
    if re.search(r'xrt::mailbox', decl):
        headers.add("xrt/experimental/xrt_mailbox.h")
    if re.search(r'xrt::module', decl):
        headers.add("xrt/experimental/xrt_module.h")
    if re.search(r'xrt::runlist', decl):
        headers.add("xrt/experimental/xrt_kernel.h")
    if re.search(r'xrt::profile', decl):
        headers.add("xrt/experimental/xrt_profile.h")
    if re.search(r'xrt::queue', decl):
        headers.add("xrt/experimental/xrt_queue.h")
    if re.search(r'xrt::error', decl):
        headers.add("xrt/experimental/xrt_error.h")
    if re.search(r'xrt::ext::', decl):
        headers.add("xrt/experimental/xrt_ext.h")
    if re.search(r'xrt::ini::', decl):
        headers.add("xrt/experimental/xrt_ini.h")
    if re.search(r'xrt::message::', decl):
        headers.add("xrt/experimental/xrt_message.h")
    if re.search(r'xrt::system::', decl):
        headers.add("xrt/experimental/xrt_system.h")
    if re.search(r'xrt::aie::program', decl):
        headers.add("xrt/experimental/xrt_aie.h")
    if re.search(r'xrt::version', decl):
        headers.add("xrt/experimental/xrt_version.h")
    if re.search(r'xrt_core::fence_handle', decl):
        headers.add("core/common/api/fence_int.h")
    if re.search(r'xrt_core::fence_handle', decl):
        headers.add("core/common/api/fence_int.h")
    return list(headers)

def gen_decl_cpp(decl: str, cpp_file: str):
    print(f"generate cpp for {decl} to file {cpp_file}")
    sfunc_return = dict()
    sfunc_return[r"operator xrt_core::hwctx_handle"] = "return nullptr;"
    sfunc_return[r"operator xclDeviceHandle"] = "return nullptr;"
    sfunc_return[r'xrt::xclbin_repository::iterator\s*&*\s*[\w:&+->*]+\s*\(.*\)'] = "throw std::runtime_error(\"unsupported\");"
    sfunc_return[r'xrt::bo::async_handle\s*&*\s*[\w+:&+->]+\s*\(.*\)'] = "throw std::runtime_error(\"unsupported\");"
    sfunc_return[r'xrt::ip::interrupt\s*&*\s*[\w+:&+->]+\s*\(.*\)'] = "throw std::runtime_error(\"unsupported\");"
    with open(cpp_file, 'w') as cpp:
        headers = get_class_header(decl)
        for h in headers:
            cpp.write("#include <stdexcept>\n")
            cpp.write(f"#include \"{h}\"\n")
            if "boost::any" in decl:
                cpp.write("#include <boost/any.hpp>\n")
        cpp.write(f"\n{decl}\n")
        match = re.search(r'(.*[\w>&*]\s+)?\s*[\s\w:]+operator[\s\w&*=+->]+\s*\(.*\)(\s*[\w\s]+)?$', decl)
        if not match:
            match = re.search(r'(.*[\w>&*]\s+)?\s*[~\w:]+\(.*\)(\s*[\w\s]+)?$', decl)
        # special handling
        has_special_handling = False
        for key, val in sfunc_return.items():
            if re.search(key, decl):
                cpp.write(f"{{\n{val}\n}}\n")
                has_special_handling = True
                break
        if not has_special_handling:
            ret_type = match.group(1)
            if not ret_type or ret_type.strip() == "void":
                if not has_special_handling:
                    # no return type
                    cpp.write("{}\n")
            else:
                ret_type = ret_type.strip()
                # TODO: will add return type with & support if there is such as case
                if ret_type.endswith("&"):
                    ret_type = re.sub(r'const\s', '', ret_type)
                    ret_type = re.sub(r'constexpr\s', '', ret_type).strip()
                    cpp.write(f"{{\n  static {ret_type[:-1]} dummy;\n  return dummy;\n}}\n")
                elif ret_type.endswith("*"):
                    cpp.write("{return nullptr;}\n")
                else:
                    cpp.write("{return {};}\n")
        cpp.close()

def build_cpp_get_mangled(build_dir, script_dir, xrt_src_root):
    bdir = build_dir
    sdir = script_dir + "/ch_mangled"
    shutil.copyfile(f"{sdir}/CMakeLists.txt", f"{bdir}/CMakeLists.txt")
    # Needs to create xrt/detail to hold the generated version.h from XRT CMake
    os.makedirs(f"{bdir}/xrt/detail", exist_ok=True)
    if is_windows():
        xrt_boost_root="C:/Xilinx/XRT/ext.new"
        subprocess.run(['cmake', '-B', bdir, '-S', bdir, f"-DXRT_BOOST_INSTALL={xrt_boost_root}", f"-DXRT_SOURCE_DIR={xrt_src_root}"], check=True)
    else:
        subprocess.run(['cmake', '-B', bdir, '-S', bdir, f"-DXRT_SOURCE_DIR={xrt_src_root}"], check=True)
    subprocess.run(['cmake', '--build', bdir, '-j'], check=True)

def get_obj_mangled_name_win(obj_f, func_match_name):
    # one object file contains only one function
    result = subprocess.run(
        ["dumpbin", "/SYMBOLS", obj_f], capture_output=True, text=True, check=True)
    for line in result.stdout.splitlines():
        if "External" in line and func_match_name in line:
            mangled_name = line.split('|')[1].split()[0]
            return mangled_name
    return None

def get_obj_mangled_name_linux(obj_f, func_match_name):
    # one object file contains only one function
    result = subprocess.run(
        f"nm {obj_f} | grep \" T \"", shell=True, capture_output=True, text=True, check=True)
    cppfilt = subprocess.run(f"nm {obj_f} | grep \" T \" | c++filt", shell=True, capture_output=True, text=True, check=True)

    mangled_names = []
    func_addr = []
    for line, readable in zip(result.stdout.splitlines(), cppfilt.stdout.splitlines()):
        if func_match_name in readable:
            mangled_names.append(line.split(' T ')[1])
            func_addr.append(line.split(' T ')[0])
    if not mangled_names:
        return None
    if len(mangled_names) > 1:
        if len(set(func_addr)) > 1:
            # in case of constructor, there can be base object constructor and complete object constructor
            # For now, we only use base object constructor
            # For Linux, we use preload library, should be fine to call the base object constructor
            sys.exit(f"{func_match_name} has more than one different address in {obj_f}")
        return sorted(mangled_names)[1]
    return mangled_names[0]

def get_obj_mangled_name(obj_f, func_name):
    # we have this opeorator override: xrt::device::operator xclDeviceHandle
    # in this case, function name detected by script will be xclDeviceHandle, but
    # what's come out from compiler can be the type aliased by the `xclDeviceHandle`
    # in this case, just check the operator
    omatch = re.search(r'(\w[\w:]*::operator)\s', func_name)
    if omatch:
        func_match_name = omatch.group(1)
    else:
        func_match_name = func_name
    if is_windows():
        return get_obj_mangled_name_win(obj_f, func_match_name)
    else:
        return get_obj_mangled_name_linux(obj_f, func_match_name)

def find_file(root_dir, base_name):
    for dirpath, _, files in os.walk(root_dir):
        for file in files:
            if file == base_name:
                return os.path.join(dirpath, file)
    return None

def sort_funcs(funcs: set):
    func_info_list = []
    for f in funcs:
        finfo = parse_cpp_func_args.get_func_info(f)
        finfo['decl'] = f
        func_info_list.append(finfo)
    return sorted(func_info_list, key=lambda item: item['func'])

def gen_mangled_funcs_names(funcs: set, xrt_src_root, script_dir: str, build_dir: str, out_cpp: str):
    ffile_map = dict()
    i = 0
    bdir = build_dir + "/ch_mangled"
    os.makedirs(f"{bdir}/src", exist_ok=True)
    func_info_list = sort_funcs(funcs)
    #print(f"get mangled functions names:\n {func_info_list}")
    for finfo in func_info_list:
        fname=f"gen_temp_{i}"
        cpp_file = f"{bdir}/src/{fname}.cpp"
        ffile_map[finfo['decl']] = fname
        gen_decl_cpp(finfo['decl'], cpp_file)
        i = i + 1

    # Compile CPP
    build_cpp_get_mangled(build_dir=bdir, script_dir=script_dir, xrt_src_root=xrt_src_root)
    # get mangled name from generated result
    fmangled_map = dict()
    for decl, cpp in ffile_map.items():
        if is_windows():
            obj_name = cpp + ".obj"
        else:
            obj_name = cpp + ".cpp.o"
        obj_file = find_file(bdir, obj_name)
        if not obj_file:
            sys.exit("failed to locate " + obj_name)
        func_info = parse_cpp_func_args.get_func_info(decl)
        func_s = func_info['func'] + "("
        if 'arg' in func_info:
            args_types_list = []
            for a in func_info['arg']:
                args_types_list.append(a[0])
            args_str = ', '.join(args_types_list)
        else:
            args_str = "void"
        func_s = func_s + args_str + ")"
        func_n = func_info['func']
        mname = get_obj_mangled_name(obj_file, func_n)
        if not mname:
            sys.exit(f"not find mangled name in {obj_file} for function: {decl}, func: {func_n}")
        fmangled_map[func_s] = mname

    print(f"wrting function name to mangled name mapping to \'{out_cpp}\'.")
    # output the demangled name and the mangled name to a cpp array
    with open(out_cpp, 'w') as out:
        if is_windows():
          out.write("#ifdef _WIN32\n")
        else:
          out.write("#ifdef __linux__\n")
        out.write("#include <cstring>\n\n")
        out.write("const char * func_mangled_map[] = {\n")
        for k, m in fmangled_map.items():
            out.write(f"\t\"{k}\", \"{m}\",\n")
        out.write("};\n")
        out.write("#endif\n")

def get_lib_exports_linux(lib_file):
    lib_exports = subprocess.run(
        f"nm {lib_file} | grep \" T \"", shell=True, capture_output=True, text=True, check=True)
    return lib_exports.stdout
    

def compare_lib_exports_win(mangled_names_file, lib_file):
    lib_exports = subprocess.run(
        ["dumpbin", "/EXPORTS", lib_file], capture_output=True, text=True, check=True)
    return lib_exports.stdout

def compare_lib_mangled_names(mangled_names_file, lib_file):
    if is_windows():
        lib_exports = get_lib_exports_win(lib_file)
    else:
        lib_exports = get_lib_exports_linux(lib_file)

    with open(mangled_names_file, 'r', encoding='utf-8') as mfile:
        lines = mfile.readlines()
        for line in lines:
            if ", \"" not in line:
                continue
            mname = re.search(r".*, \"(.*)\",", line)
            if not mname:
                sys.exit(f"compared mangled name failed, failed to get mangled name from {line}")
            mname = mname.group(1)
            if not re.search(r"\s{mname}\s|$", lib_exports):
                #sys.exit(f"manged name \'{mname}\' not in \'{lib_file}\'")
                print(f"manged name \'{mname}\' not in \'{lib_file}\'")
    print(f"compare mangled names from \'{mangled_names_file}\' to \'{lib_file}\' done.")
