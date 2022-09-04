#!/usr/bin/env python3

import sys
import subprocess

iota_counter=0
def iota(reset=False):
    global iota_counter
    if reset:
        iota_counter = 0
    result = iota_counter
    iota_counter += 1
    return result

OP_PUSH = iota(True)
OP_PLUS = iota()
OP_MINUS = iota()
OP_DUMP = iota()
COUNT_OPS = iota()

def push(x):
    return (OP_PUSH, x)

def plus():
    return (OP_PLUS, )

def minus():
    return (OP_MINUS, )

def dump():
    return (OP_DUMP, )

def simulate_program(program):
    stack = []
    for op in program:
        assert COUNT_OPS == 4, "Exhaustive handling of oprations in simulation"

        if op[0] == OP_PUSH:
            if len(op) < 2:
                assert False, "no push value"
            stack.append(op[1])
        elif op[0] == OP_PLUS:
            a = stack.pop()
            b = stack.pop()
            stack.append(a + b)
        elif op[0] == OP_MINUS:
            a = stack.pop()
            b = stack.pop()
            stack.append(b - a)
        elif op[0] == OP_DUMP:
            a = stack.pop()
            print(a)
        else:
            assert False, "unreachable"

def compile_program(program, out_file_path):
        with open(out_file_path, "w") as out:
            assert COUNT_OPS == 4, "Exhaustive handling of oprations in compilation"

            out.write("""
segment .text
dump:
    mov     r8, -3689348814741910323
    sub     rsp, 40
    mov     BYTE [rsp+31], 10
    lea     rcx, [rsp+30]
.L2:
    mov     rax, rdi
    mul     r8
    mov     rax, rdi
    shr     rdx, 3
    lea     rsi, [rdx+rdx*4]
    add     rsi, rsi
    sub     rax, rsi
    mov     rsi, rcx
    sub     rcx, 1
    add     eax, 48
    mov     BYTE [rcx+1], al
    mov     rax, rdi
    mov     rdi, rdx
    cmp     rax, 9
    ja      .L2
    lea     rdx, [rsp+32]
    mov     edi, 1
    sub     rdx, rsi
    mov     rax, 0x01
    syscall
    add     rsp, 40
    ret
global _start
_start:
            \n""")

            for op in program:
                if op[0] == OP_PUSH:
                    if len(op) < 2:
                        assert False, "no push value"
                    out.write(f"""
;; -- push {op[1]} --
    push {op[1]}
                    """)
                elif op[0] == OP_PLUS:
                    out.write("""
;; -- plus --
    pop rax
    pop rbx
    add rax, rbx
    push rax
                    \n""")
                elif op[0] == OP_MINUS:
                    out.write("""
;; -- minus --
    pop rax
    pop rbx
    sub rbx, rax
    push rbx
                    \n""")
                elif op[0] == OP_DUMP:
                    out.write("""
;; -- dump --
    pop rdi
    call dump
                    \n""")
                else:
                    assert False, "unreachable"

            out.write("""
;; -- exit --
    mov rax, 0x3c
    mov rdi, 0
    syscall
            """)

is_comment = False
comment_row = 0
def parse_word_as_op(token):
    global is_comment
    global comment_row
    assert COUNT_OPS == 4, "Exhaustive handeling in parse_word_as_op"
    # Comment handeling
    if is_comment and comment_row == token[1]:
        return None
    else:
        is_comment == False
    if '//' in token[3]:
        is_comment = True
        comment_row = token[1]
        return None
    # Op handeling
    if token[3] == '+':
        return plus()
    if token[3] == '-':
        return minus()
    if token[3] == '.':
        return dump()
    if token[3].isspace():
        return None
    try:
        return push(int(token[3]))
    except Exception as e:
        print( f"SyntaxError: in {token[0]} at ({token[1]}, {token[2]}) {token[3]} is not valid syntax\n{e}" )
        exit(1)

def find_col(line, start, predicate):
    while start < len(line) and not predicate(line[start]):
        start += 1
    return start

def lex_line(line):
    col = find_col(line, 0, lambda x: not x.isspace())
    while col < len(line):
        col_end = find_col(line, col, lambda x: x.isspace())
        yield (col, line[col:col_end])
        col = find_col(line, col_end, lambda x: not x.isspace())

def lex_file(file_path):
    lex = []
    with open(file_path, "r") as file:
        return [(file_path, row+1, col, token)
                for (row, line) in enumerate(file.readlines())
                for (col, token) in lex_line(line)]

def load_program_from_file(program_path):
    return list(filter(lambda x: not x == None, [parse_word_as_op(token) for token in lex_file(program_path)]))

def usage(program):
        print(f"""
Usage: {program} <SUBCOMMAND> [ARGS]
SUBCOMMANDS:
    - sim <file>  -- Simulate the program
    - com <file>  -- Compile the program
        """)

def call_cmd(cmd):
    print(cmd)
    subprocess.call(cmd.split(' '))

def uncons(xs):
    return (xs[0], xs[1:])

if __name__ == '__main__':
    argv = sys.argv

    assert len(argv) >= 1, "No program"

    (program_name, argv) = uncons(argv)
    if len(argv) < 1:
        usage(program_name)
        print("ERROR: no subcomand provided")
        exit(1)

    (subcommand, argv) = uncons(argv)

    if subcommand == 'sim' or subcommand == 'simulate':
        if len(argv) < 1:
            usage(program_name)
            print("ERROR: No input file for the simulation")
            exit(1)
        (program_path, argv) = uncons(argv)
        program = load_program_from_file(program_path)
        print(program)
        simulate_program(program)
    elif subcommand == 'com' or subcommand == 'compile':
        if len(argv) < 1:
            usage(program)
            print("ERROR: No input file for the compilation")
            exit(1)
        (program_path, argv) = uncons(argv)
        program = load_program_from_file(program_path)
        compile_program(program, "output.asm")
        call_cmd("nasm -felf64 output.asm")
        call_cmd("ld -o output output.o")
        call_cmd("rm -rf output.o")
    else:
        usage(program_name)
        assert False, f"Unknown subcommand, {subcommand}"
