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

def mem_init_construct(decl: str):
    if re.search(r"aie_error::aie_error\(", decl):
        full_args_list = re.search(r"\((.*)\)", decl).group(1).split(',')
        args_list = []
        for a in full_args_list:
            aname = re.search(r"\s[\*&]*(\w+)$", a).group(1)
            args_list.append(aname)
            args_str = ','.join(args_list)
        return f": command_error({args_str})"
    return None

def gen_decl_cpp(decl: str, cpp_file: str):
    print(f"generate cpp for {decl} to file {cpp_file}")
    sfunc_return = dict()
    sfunc_return[r"operator xrt_core::hwctx_handle"] = "return nullptr;"
    sfunc_return[r"operator xclDeviceHandle"] = "return nullptr;"
    sfunc_return[r'xrt::xclbin_repository::iterator\s*&*\s*[\w:&+->*]+\s*\(.*\)'] = "throw std::runtime_error(\"unsupported\");"
    sfunc_return[r'xrt::bo::async_handle\s*&*\s*[\w+:&+->]+\s*\(.*\)'] = "throw std::runtime_error(\"unsupported\");"
    sfunc_return[r'xrt::ip::interrupt\s*&*\s*[\w+:&+->]+\s*\(.*\)'] = "throw std::runtime_error(\"unsupported\");"
    with open(cpp_file, 'w') as cpp:
        cpp.write("#include <stdexcept>\n")
        headers = get_class_header(decl)
        for h in headers:
            cpp.write(f"#include \"{h}\"\n")
            if "boost::any" in decl:
                cpp.write("#include <boost/any.hpp>\n")
        cpp.write(f"\n{decl}\n")
        mem_init = mem_init_construct(decl)
        if mem_init:
            cpp.write(f"{mem_init}")
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
        fmangled_map = dict(sorted(fmangled_map.items()))
        for k, m in fmangled_map.items():
            out.write(f"\t\"{k}\", \"{m}\",\n")
        out.write("};\n")
        out.write("#endif\n")

def get_lib_exports_linux(lib_file):
    lib_exports = subprocess.run(
        f"nm {lib_file} | grep \" T \"", shell=True, capture_output=True, text=True, check=True)
    return lib_exports.stdout
    

def get_lib_exports_win(lib_file):
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

def gen_wrapper_funcs(funcs: set, class_dict: dict, out_cpp_dir: str):
    os.makedirs(f"{out_cpp_dir}", exist_ok=True)
    func_info_list = sort_funcs(funcs)
    class_file_map = dict()
    class_file_map['xrt'] = "hook_xrt.cpp"
    class_file_map['xrt::aie'] = "hook_xrt_aie.cpp"
    class_file_map['xrt::bo'] = "hook_xrt_bo.cpp"
    class_file_map['xrt::device'] = "hook_xrt_device.cpp"
    class_file_map['xrt::elf'] = "hook_xrt_elf.cpp"
    class_file_map['xrt::error'] = "hook_xrt_error.cpp"
    class_file_map['xrt::ext::bo'] = "hook_xrt_ext_bo.cpp"
    class_file_map['xrt::ext::kernel'] = "hook_xrt_ext_kernel.cpp"
    class_file_map['xrt::fence'] = "hook_xrt_fence.cpp"
    class_file_map['xrt::hw_context'] = "hook_xrt_hw_context.cpp"
    class_file_map['xrt::ini'] = "hook_xrt_ini.cpp"
    class_file_map['xrt::ip'] = "hook_xrt_ip.cpp"
    class_file_map['xrt::kernel'] = "hook_xrt_kernel.cpp"
    class_file_map['xrt::mailbox'] = "hook_xrt_mailbox.cpp"
    class_file_map['xrt::module'] = "hook_xrt_module.cpp"
    class_file_map['xrt::message'] = "hook_xrt_message.cpp"
    class_file_map['xrt::profile'] = "hook_xrt_profile.cpp"
    class_file_map['xrt::queue'] = "hook_xrt_queue.cpp"
    class_file_map['xrt::run'] = "hook_xrt_run.cpp"
    class_file_map['xrt::runlist'] = "hook_xrt_runlist.cpp"
    class_file_map['xrt::system'] = "hook_xrt_system.cpp"
    class_file_map['xrt::version'] = "hook_xrt_version.cpp"
    class_file_map['xrt::xclbin'] = "hook_xrt_xclbin.cpp"
    class_file_map['xrt::xclbin_repository'] = "hook_xrt_xclbin.cpp"

    func_file_map = dict()
    func_file_map["xrt::operator==(const xrt::device&, const xrt::device&)"] = "hook_xrt_device.cpp"
    func_file_map["xrt::set_read_range(const xrt::kernel&, uint32_t, uint32_t)"] = "hook_xrt_kernel.cpp"

    # get mangled name from generated result
    if is_windows():
        mangled_names_file = out_cpp_dir + "/funcs_mangled_lookup_win.cpp"
    else:
        mangled_names_file = out_cpp_dir + "/funcs_mangled_lookup_linux.cpp"

    fmangled_map = dict()
    with open(mangled_names_file, 'r', encoding='utf-8') as mfile:
        lines = mfile.readlines()
        for line in lines:
            if "\", \"" not in line:
                continue
            match = re.search(r"\"(.*)\", \"(.*)\",", line)
            if not match:
                sys.exit(f"compared mangled name failed, failed to get mangled name from {line}")
            fsignature = match.group(1)
            fmname = match.group(2)
            fmangled_map[fsignature] = fmname

    hook_xrt_h_f = out_cpp_dir + "/hook_xrt.h"
    xrt_headers = set()
    xrt_headers.add("chrono")
    xrt_headers.add("typeinfo")
    xrt_headers.add("xrt.h")
    xrt_headers.add("xrt/xrt_bo.h")
    xrt_headers.add("xrt/xrt_aie.h")
    xrt_headers.add("xrt/xrt_device.h")
    xrt_headers.add("xrt/xrt_hw_context.h")
    xrt_headers.add("xrt/xrt_kernel.h")
    xrt_headers.add("xrt/xrt_uuid.h")
    xrt_headers.add("xrt/experimental/xrt_ip.h")
    xrt_headers.add("xrt/experimental/xrt_mailbox.h")
    xrt_headers.add("xrt/experimental/xrt_module.h")
    xrt_headers.add("xrt/experimental/xrt_kernel.h")
    xrt_headers.add("xrt/experimental/xrt_profile.h")
    xrt_headers.add("xrt/experimental/xrt_queue.h")
    xrt_headers.add("xrt/experimental/xrt_error.h")
    xrt_headers.add("xrt/experimental/xrt_ext.h")
    xrt_headers.add("xrt/experimental/xrt_ini.h")
    xrt_headers.add("xrt/experimental/xrt_message.h")
    xrt_headers.add("xrt/experimental/xrt_system.h")
    xrt_headers.add("xrt/experimental/xrt_aie.h")
    xrt_headers.add("xrt/experimental/xrt_version.h")
    xrt_headers.add("core/common/api/fence_int.h")
    xrt_headers.add("google/protobuf/timestamp.pb.h")
    xrt_headers.add("func.pb.h")
    xrt_headers.add("common/trace_utils.h")
    with open(hook_xrt_h_f, 'w', newline='\n') as out:
        for h in xrt_headers:
            out.write(f"#include <{h}>\n")

    for decl in funcs:
        func_info = parse_cpp_func_args.get_func_info(decl)
        if 'return' in func_info:
            func_ret = func_info['return']
        else:
            func_ret = None
        if 'props' in func_info:
            func_p = func_info['props']
        func_s = func_info['func'] + "("
        if 'arg' in func_info:
            args_types_list = []
            for a in func_info['arg']:
                args_types_list.append(a[0])
            args_str = ', '.join(args_types_list)
        else:
            args_str = "void"
        func_s = func_s + args_str + ")"
        func_name = func_info['func']
        mname = fmangled_map[func_s]
        if not mname:
            sys.exit(f"failed to get mangled name for \'{func_s}\'.")
        func_c_match = re.search(r"([\w:]+)::operator\s+([\w:*&\s]+)$", func_name);
        if not func_c_match:
            func_c_match = re.search(r"([\w:]+)::([\w=\*&\-\+<>\s~]+)$", func_name)
        func_f = None
        if func_c_match:
            func_c = func_c_match.group(1)
            func_n = func_c_match.group(2)
        else:
            sys.exit(f"function\'{decl}\', func_name: \'{func_name}\', doesn't have class information.")
        if func_c_match:
            func_c_tmp = func_c_match.group(1).split("::")
            while func_c_tmp:
                func_c_tmp_str = "::".join(func_c_tmp)
                if func_c_tmp_str in class_file_map:
                    func_f = class_file_map[func_c_tmp_str]
                    break
                func_c_tmp.pop()
        if not func_f:
            if func_s in func_file_map:
                func_f = func_file_map[func_s]
        if not func_f:
            sys.exit(f"failed to get generated cpp file for \'{func_n}\', class: {func_c}.")
        if not os.path.exists(func_f):
            with open(func_f, 'w', newline='\n') as out:
                out.write("#include <wrapper/hook_xrt.h>\n")
        args_list = []
        if 'arg' in func_info:
            for a in func_info['arg']:
                args_list.append(' '.join(a))
        args_str = ','.join(args_list)
        with open(func_f, 'a', newline='\n') as out:
            print(f"gen hook: \"{func_f}\"")
            out.write("\n")
            if func_ret:
                out.write(f"{func_ret}\n")
            lines = f"""
{func_c}::
{func_n}({args_str})
{{
  xbtracer_proto::Func func;
  func.set_name("{func_s}");
  auto now = std::chrono::system_clock::now();
  auto duration = now.time_since_epoch();
  auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
  auto micros = std::chrono::duration_cast<std::chrono::microseconds>(duration - seconds);

  google::protobuf::Timestamp* ts = func.mutable_timestamp();
  ts->set_seconds(seconds.count());
  ts->set_nanos(micros.count() * 1000); // Convert microseconds to nanoseconds

  uint32_t pid = getpid_current_os();
  func.set_pid(pid);
  func.set_status(xbtracer_proto::Func::FuncStatus::FUNC_ENTRY);
"""
            out.write(f"{lines}")
            if func_c in class_dict:
                # TODO: how about static class function, we need detection in future too
                if class_dict[func_c] == "class":
                    # add handle to the arguments
                    lines = f"""
  auto this_pimpl = this->get_handle();
  void* this_pimpl_ptr = this_impl->get();
  xbtracer_proto::Arg* arg = func.add_arg();
  arg->set_name("pimpl")
  arg->set_type("void*")
  arg->set_size(static_cast<uint32_t>(sizeof(void*) & 0xFFFFFFFFU));
  arg->set_value(std::string(reinterpret_cast<const char*>(&this_pimpl_ptr), sizeof(this_pimpl_ptr)));
"""
                    out.write(f"{lines}")
            lines = f"""
  xbtracer_write_protobuf_msg(func);
"""
            out.write(f"{lines}")
            out.write("}\n")
