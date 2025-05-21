#!/usr/bin/env python3

import argparse
import os
import re
import sys

def get_cpp_files(root_dir):
    cpp_files = []
    for dirpath, _, filenames in os.walk(root_dir):
        for f in filenames:
            if f.endswith('.cpp'):
                cpp_files.append(os.path.join(dirpath, f))
    return cpp_files

def get_header_files(header_dir):
    header_files = []
    for dirpath, _, filenames in os.walk(header_dir):
        for f in filenames:
            if f.endswith('.h') or f.endswith('.hpp'):
                header_files.append(os.path.join(dirpath, f))
    return header_files

def read_file_skip_comments(file_path):
    with open(file_path, 'r') as file:
        content = file.read()

    # Regular expression to match C++ comments
    # Matches single-line comments (//) and multi-line comments (/* */)
    comment_pattern = r'//.*?$|/\*.*?\*/'
    
    # Remove comments using re.sub
    cleaned_content = re.sub(comment_pattern, '', content, flags=re.DOTALL | re.MULTILINE)
    
    # Split into lines and strip whitespace
    lines = [line.strip() for line in cleaned_content.splitlines() if line.strip()]
    
    return lines

namespace_pattern = re.compile(r'\s*namespace\s+([\w+:]+)\s*{')
class_pattern = re.compile(r'^\s*class\s+(\w+)\s*(:.+)?\s*{')
func_export_pattern = r"\s*(XCL_DRIVER_DLLESPEC|XRT_API_EXPORT)"
func_h_pattern = re.compile(
    r'''(?P<export>\s*XCL_DRIVER_DLLESPEC|XRT_API_EXPORT)\s+  # export disclaimer
        (?P<ret_type>[a-zA-Z_][\w:<>\s*&~\*,]*\s+)?    # return type (may be empty for ctor/dtor)
        (?P<class>[a-zA-Z_][\w:]*::)?               # optional class name
        (?P<func>[~]?[a-zA-Z_]\w*)\s*               # function name (may start with ~ for dtor)
        \((?P<args>[\(\)\w\*&,:<>\s=.{}]*)\)\s*                     # arguments
        (?P<props>(?:const)?\s*(?:noexcept)?\s*(?:override)?)\s*    # properties
        (?P<mem_init>:\s*[a-zA-Z]\w+\s*\(.+\))?\s*  # member initialization of contructor
        (?:\{|;)                                    # function body or declaration
    ''', re.VERBOSE | re.DOTALL
)
func_c_pattern = re.compile(
    r'''(?P<export>\s*XCL_DRIVER_DLLESPEC|XRT_API_EXPORT|XCL_DRIVER_DLLESPEC\s+)?  # export disclaimer
        (?P<ret_type>[a-zA-Z_][\w:<>\s*&~\*,]*\s+)?    # return type (may be empty for ctor/dtor)
        (?P<class>[a-zA-Z_][\w:]*::)?               # optional class name
        (?P<func>[~]?[a-zA-Z_]\w*)\s*               # function name (may start with ~ for dtor)
        \((?P<args>[\(\)\w\*&,:<>\s=.{}]*)\)\s*                     # arguments
        (?P<props>(?:const)?\s*(?:noexcept)?\s*(?:override)?)\s*    # properties
        (?P<mem_init>:\s*[a-zA-Z]\w+\s*\(.+\))?\s*  # member initialization of contructor
        (?:\{)                                    # function body or declaration
    ''', re.VERBOSE | re.DOTALL
)
operator_h_pattern = re.compile(
    r'''(?P<export>\s*XCL_DRIVER_DLLESPEC|XRT_API_EXPORT)\s+  # export disclaimer
        (?P<ret_type>[a-zA-Z_][\w:<>\s*&~\*,]*\s+)?    # return type (may be empty for ctor/dtor)
        (?P<class>[a-zA-Z_][\w:]*::)?               # optional class name
        (?P<op>operator\s*.*)\s*               # operator name
        \((?P<args>[\(\)\w\*&,:<>\s=.{}]*)\)\s*                     # arguments
        (?P<props>(?:const)?\s*(?:noexcept)?\s*(?:override)?)\s*    # properties
        (?:\{|;)                                    # function body or declaration
    ''', re.VERBOSE | re.DOTALL
)
operator_c_pattern = re.compile(
    r'''(?P<export>\s*XCL_DRIVER_DLLESPEC|XRT_API_EXPORT\s+)?  # export disclaimer
        (?P<ret_type>[a-zA-Z_][\w:<>\s*&~\*,]*\s+)?    # return type (may be empty for ctor/dtor)
        (?P<class>[a-zA-Z_][\w:]*::)?               # optional class name
        (?P<op>operator\s*.*)\s*               # operator name
        \((?P<args>[\(\)\w\*&,:<>\s=.{}]*)\)\s*                     # arguments
        (?P<props>(?:const)?\s*(?:noexcept)?\s*(?:override)?)\s*    # properties
        (?:\{)                                    # function body or declaration
    ''', re.VERBOSE | re.DOTALL
)
    
def extract_functions_from_file(file, is_header):
    if is_header == 1:
        func_pattern = func_h_pattern
        operator_pattern = operator_h_pattern
    else:
        func_pattern = func_c_pattern
        operator_pattern = operator_c_pattern

    scope_stack = []
    decls = set()
    print(f"***** trying to extract functions from {file} ******")
    #with open(header_file, 'r', encoding='utf-8', errors='ignore') as f:
    #    lines = f.readlines()
    lines = read_file_skip_comments(file)
    brackets_scope_stack = []
    start_scope_pattern = re.compile(r'{')
    end_scope_pattern = re.compile(r'}')
    acc_lines = []
    for index, line in enumerate(lines):
        if re.search(r'^\s*#', line):
           # skip compilation macro
           acc_lines = []
           continue
        acc_lines.append(line.strip())
        lines_joined = ' '.join(acc_lines)
        lines_joined = re.sub(r'\s*::\s*', '::', lines_joined)
        ns_matches = namespace_pattern.finditer(lines_joined)
        if re.search(r'^\s*namespace\s+', lines_joined):
            is_ns = 0
            for ns_match in ns_matches:
                #print(f"add namespace: {ns_match.group(1)}")
                is_ns = 1
                scope_stack.append(ns_match.group(1))
                brackets_scope_stack.append(f"namespace,{ns_match.group(1)}")
            if is_ns == 1:
                acc_lines = []
            continue
        cls_match = class_pattern.search(lines_joined)
        if cls_match:
            #print(f"add class: {cls_match.group(1)}")
            scope_stack.append(cls_match.group(1))
            brackets_scope_stack.append(f"class,{cls_match.group(1)}")
            acc_lines = []
            continue
        elif re.search(r'^\s*class\s+(?!.*;)', lines_joined):
            continue
        #print(f"func check lines joined: {lines_joined}")
        func_match = func_pattern.search(lines_joined)
        if re.search(r'(\s*if\s*\()|(\s*while\s*\()(\s*catch\s*\()', line):
            acc_lines = []
        elif func_match:
            export_name = func_match.group('export')
            ret_type = func_match.group('ret_type')
            if ret_type:
                ret_type = re.sub(r'^\s*explicit\s+', "", ret_type + " ").strip()
            else:
                ret_type = ""
            class_name = func_match.group('class')
            if class_name:
                class_name = class_name.strip()
            else:
                class_name = ""
            func_name = func_match.group('func').strip()
            args = func_match.group('args').strip()
            props = func_match.group('props').strip()
            scope = '::'.join(scope_stack) + ('::' if scope_stack else '')
            class_name = f"{scope}{class_name}"
            full_name = f"{ret_type} {class_name}{func_name}({args}) {props}".strip()
            full_name = re.sub(r'\s+', ' ', full_name)
            func_required = 1
            if "inline" in ret_type:
                func_required = 0
            if "static" in ret_type and class_name == "":
                func_required = 0
            if func_required == 1:
                #print(f"Return Type: {ret_type}, Class: {class_name}, Function: {func_name}, Args: ({args}), Properties: {props}")
                #print(f"{full_name}")
                decls.add(full_name)
            acc_lines = []
        elif is_header == 1 and not re.search(rf"^{func_export_pattern}", lines_joined):
            acc_lines = []
        else:
            op_match = operator_pattern.search(lines_joined)
            if op_match:
                export_name = op_match.group('export')
                ret_type = op_match.group('ret_type')
                if ret_type:
                    ret_type = ret_type.strip()
                else:
                    ret_type = ""
                class_name = op_match.group('class')
                if class_name:
                    class_name = class_name.strip()
                else:
                    class_name = ""
                op_name = op_match.group('op').strip()
                args = op_match.group('args').strip()
                props = op_match.group('props').strip()
                scope = '::'.join(scope_stack) + ('::' if scope_stack else '')
                class_name = f"{scope}{class_name}"
                full_name = f"{ret_type} {class_name}{op_name}({args}) {props}".strip()
                #print(f"op: {full_name}")
                decls.add(full_name)
                acc_lines = []
            elif is_header == 1 and re.search(r';|{|}', line):
                # unexpected pattern with export macro statement and the implementation is in header
                print(f"====ERROR: Unexpected pattern: {lines_joined}")
                acc_lines = []
                #sys.exit(f"==== ERROR: Unexpected pattern: {lines_joined}")
                    
        if start_scope_pattern.search(line):
            brackets_scope_stack.append("others")
            #print(f"added scope stack: others")
        if end_scope_pattern.search(line):
            if not brackets_scope_stack:
                sys.exit(f"ERROR: Unexpected bracket in line {index}, {line}")
            current_brackets_scope = brackets_scope_stack.pop()
            #print(f"pop - 0 {current_brackets_scope}")
            if re.search(r"class,|namespace,", current_brackets_scope):
                current_scope = scope_stack.pop()
                #print(f"pop {current_brackets_scope}, {current_scope}")
                if current_scope != current_brackets_scope.split(",")[1]:
                    sys.exit(f"Unmatched class/namespace scopes: {current_brackets_scropt}, {current_scope}")
    return decls

def main():
    parser = argparse.ArgumentParser(description="Scan cpp files and print functions also declared in header files.")
    parser.add_argument('--cpp_dir', help='Directory containing .cpp files')
    parser.add_argument('--header_dir', help='Directory containing header files')
    parser.add_argument('--out_header', help='Output file for the captures from header (default: stdout)', default=None)
    parser.add_argument('--out_cpp', help='Output file for the captures from cpp (default: stdout)', default=None)
    args = parser.parse_args()

    cpp_files = get_cpp_files(args.cpp_dir)
    header_files = get_header_files(args.header_dir)

    header_funcs = set()
    #header_files = []
    #header_files.append("/mnt/c/Users/wendlian/src/XRT-MCDM/build/WDebug/xilinx/xrt/include/xrt/xrt_device.h")
    for h in header_files:
        header_funcs.update(extract_functions_from_file(file=h, is_header=1))

    cpp_funcs = set()
    #cpp_files = []
    #cpp_files.append("/mnt/c/Users/wendlian/src/XRT-MCDM/src/xrt/src/runtime_src/core/tools/xbtracer/src/lib/capture.cpp")
    #cpp_files.append("/mnt/c/Users/wendlian/src/XRT-MCDM/src/xrt/src/runtime_src/core/tools/xbtracer/src/lib/xrt_kernel_inst.cpp")
    for cpp in cpp_files:
        cpp_funcs.update(extract_functions_from_file(file=cpp, is_header=0))
        #matched = cpp_funcs & header_funcs
        #for func in matched:
        #    matched_funcs.add(func)

    print(f"**** Ouputing functions from CPP *********")
    if args.out_cpp:
        with open(args.out_cpp, 'w', encoding='utf-8') as out:
            for line in sorted(cpp_funcs):
                out.write(line + '\n')
    else:
        for line in sorted(cpp_funcs):
            print(line)

    output_lines = sorted(header_funcs)
    print(f"**** Ouputing functions from Header *********")
    if args.out_header:
        with open(args.out_header, 'w', encoding='utf-8') as out:
            for line in output_lines:
                out.write(line + '\n')
    else:
        for line in output_lines:
            print(line)

if __name__ == '__main__':
    main()
