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
def extract_function_decls_from_header(header_file):
    namespace_pattern = re.compile(r'\s*namespace\s+(\w+:?:?\w+)\s*{')
    class_pattern = re.compile(r'^\s*class\s+(\w+)\s*(:.+)?\s*{')
    func_export_pattern = r"\s*(XCL_DRIVER_DLLESPEC|XRT_API_EXPORT)"
    func_pattern = re.compile(
        rf"{func_export_pattern}\s+(\w.+\s)?(~?\w.+)\s*\((.*)\)\s*(const)?\s*(noexcept)?\s*(override)?;"
        )
    scope_stack = []
    decls = set()
    print(f"***** trying to extract functions from {header_file} ******")
    with open(header_file, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    brackets_stack = []
    brackets_scope_stack = []
    start_scope_pattern = re.compile(r'{')
    end_scope_pattern = re.compile(r'}')
    acc_lines = []
    for index, line in enumerate(lines):
        acc_lines.append(line.rstrip())
        lines_joined = ' '.join(acc_lines)
        ns_matches = namespace_pattern.finditer(lines_joined)
        if re.search(r'^\s*namespace\s+', lines_joined):
            for ns_match in ns_matches:
                is_ns = 1
                print(f"add namespace: {ns_match.group(1)}")
                scope_stack.append(ns_match.group(1))
                brackets_scope_stack.append(f"namespace,{ns_match.group(1)}")
            acc_lines = []
            continue
        cls_match = class_pattern.search(lines_joined)
        if cls_match:
            print(f"add class: {cls_match.group(1)}")
            scope_stack.append(cls_match.group(1))
            brackets_scope_stack.append(f"class,{cls_match.group(1)}")
            acc_lines = []
            continue
        func_match = func_pattern.search(lines_joined)
        if func_match:
            if cls_match:
                print(f"namespace: {ns_match.group(1)} class: {cls_match.group(1)} func: {func_match.group(1)}")
            export_name = func_match.group(1)
            return_type = func_match.group(2)
            if return_type:
                return_type = return_type.replace('\n', ' ').strip()
            func_name = func_match.group(3).replace('\n', ' ').strip()
            params = func_match.group(4).replace('\n', ' ').strip()
            func_const = func_match.group(5)
            func_noexcept = func_match.group(6)
            scope = '::'.join(scope_stack) + ('::' if scope_stack else '')
            full_name = f"{scope}"
            if return_type:
                full_name = f"{full_name} {return_type}"
            full_name = f"{full_name} {func_name}({params})"
            if func_const:
                full_name = f"{full_name} {func_const}"
            if func_noexcept:
                full_name = f"{full_name} {func_noexcept}"
            #print(f"{full_name}")
            decls.add(full_name)
            acc_lines = []
            continue
        elif not re.search(rf"^{func_export_pattern}", lines_joined):
            acc_lines = []
        elif re.search(r';|{|}', line):
            # unexpected pattern with export macro statement and the implementation is in header
            print(f"====ERROR: Unexpected pattern: {lines_joined}")
            acc_lines = []
            #sys.exit(f"Unexpected pattern: {lines_joined}")
                    
        if start_scope_pattern.search(line):
            brackets_scope_stack.append("others")
            #print(f"added scope stack: others")
        if end_scope_pattern.search(line):
            if not brackets_scope_stack:
                sys.exit(f"ERROR: Unexpected bracket in line {index}, ${line}")
            current_brackets_scope = brackets_scope_stack.pop()
            #print(f"pop - 0 {current_brackets_scope}")
            if re.search(r"class,|namespace,", current_brackets_scope):
                current_scope = scope_stack.pop()
                print(f"pop {current_brackets_scope}, {current_scope}")
                if current_scope != current_brackets_scope.split(",")[1]:
                    sys.exit(f"Unmatched class/namespace scopes: {current_brackets_scropt}, {current_scope}")
    return decls

def extract_function_defs_from_cpp(cpp_file):
    # Improved regex for multi-line function definitions
    func_pattern = re.compile(
        r'(?:[\w:&*<>\[\]\s]+)?\s+([a-zA-Z_][\w:]*)\s*\(([^;{)]*)\)\s*\{', re.DOTALL)
    defs = set()
    with open(cpp_file, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
        for match in func_pattern.finditer(content):
            func_name = match.group(1)
            defs.add(func_name)
    return defs

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
    for h in header_files:
        header_funcs.update(extract_function_decls_from_header(h))

    #matched_funcs = set()
    #for cpp in cpp_files:
    #    cpp_funcs = extract_function_defs_from_cpp(cpp)
    #    matched = cpp_funcs & header_funcs
    #    for func in matched:
    #        matched_funcs.add(func)

    #output_lines = sorted(matched_funcs)
    output_lines = sorted(header_funcs)
    if args.out_header:
        with open(args.out_header, 'w', encoding='utf-8') as out:
            for line in output_lines:
                out.write(line + '\n')
    else:
        for line in output_lines:
            print(line)

if __name__ == '__main__':
    main()
