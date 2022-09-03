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

def load_program_from_file(program_path):
    program = []
    valid_syntax = True
    with open(program_path, "r") as file:
        for line in file.read().split('\n'):
            comment = False
            for op in line.split(' '):
                if comment:
                    continue
                elif "//" in op:
                    comment = True
                elif op == '.':
                    program.append(dump())
                elif op == '+':
                    program.append(plus())
                elif op == '-':
                    program.append(minus())
                elif op.isdigit():
                    program.append(push(int(op)))
                elif op == ' ' or op == '':
                    pass
                else:
                    print(f"ERROR: {op} is not valid syntax")
                    valid_syntax = False
    assert valid_syntax, "Syntax Error"
    return program

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
