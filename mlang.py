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

# TODO: unhardcode program (load from file)
program = [
    push(34),
    push(35),
    plus(),
    dump(),

    push(500),
    push(80),
    minus(),
    dump(),
]

def usage():
        print("""
Usage: mlang.py <SUBCOMMAND> [ARGS]
SUBCOMMANDS:
    - sim  -- Simulate the program
    - com  -- Compile the program
        """)

def call_cmd(cmd):
    print(cmd)
    subprocess.call(cmd.split(' '))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        usage()
        print("ERROR: no subcomand provided")
        exit(1)

    subcommand = sys.argv[1]
    if subcommand == 'sim':
        simulate_program(program)
    elif subcommand == 'com':
        compile_program(program, "output.asm")
        call_cmd("nasm -felf64 output.asm")
        call_cmd("ld -o output output.o")
        call_cmd("rm -rf output.o")
    else:
        usage()
        assert False, f"Unknown subcommand, {subcommand}"
