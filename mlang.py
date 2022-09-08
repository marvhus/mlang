#!/usr/bin/env python3

iota_counter=0
def iota(reset=False):
    global iota_counter
    if reset:
        iota_counter = 0
    result = iota_counter
    iota_counter += 1
    return result

OP_PUSH     = iota(True) # 0
OP_PLUS     = iota()     # 1
OP_MINUS    = iota()     # 2
OP_EQUAL    = iota()     # 3
OP_DUMP     = iota()     # 4
OP_IF       = iota()     # 5
OP_ELSE     = iota()     # 6
OP_END      = iota()     # 7
OP_DUP      = iota()     # 8
OP_GREATER  = iota()     # 9
OP_LESS     = iota()     # 10
OP_WHILE    = iota()     # 11
OP_DO       = iota()     # 12
COUNT_OPS   = iota()     #

def simulate_program(program):
    stack = []
    ip = 0
    while ip < len(program):
        assert COUNT_OPS == 13, "Exhaustive handling of oprations in simulation"

        op = program[ip]

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
        elif op[0] == OP_EQUAL:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(a == b))
        elif op[0] == OP_DUMP:
            a = stack.pop()
            print(a)
        elif op[0] == OP_IF:
            assert len(op) >= 2, "`if` instruction does not have reference to the end of it's block. Please call crossrefernce_blocks() on the program before trying to simulate it"
            a = stack.pop()
            if a == 0:
                ip = op[1]
        elif op[0] == OP_ELSE:
            assert len(op) >= 2, "`else` instruction does not have reference to the end of it's block. Please call crossrefernce_blocks() on the program before trying to simulate it"
            ip = op[1]
        elif op[0] == OP_END:
            if len(op) >= 2:
                ip = op[1]
            pass
        elif op[0] == OP_DUP:
            stack.append(stack[-1])
        elif op[0] == OP_GREATER:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(b > a))
        elif op[0] == OP_LESS:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(b < a))
        elif op[0] == OP_WHILE:
            pass
        elif op[0] == OP_DO:
            assert len(op) >= 2, "`do` instruction does not have reference to the end of it's block. Please call crossrefernce_blocks() on the program before trying to simulate it"
            a = stack.pop()
            if a == 0:
                ip = op[1]
        else:
            print(op)
            assert False, "unreachable"

        ip += 1

def compile_program(program, out_file_path):
        with open(out_file_path, "w") as out:
            assert COUNT_OPS == 13, "Exhaustive handling of oprations in compilation"

            out.write("""
BITS 64
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
            """)
##### LOOP OVER OPs IN PROGRAM
            for ip, op in enumerate(program):
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
                    """)
                elif op[0] == OP_MINUS:
                    out.write("""
;; -- minus --
    pop rax
    pop rbx
    sub rbx, rax
    push rbx
                    """)
                elif op[0] == OP_EQUAL:
                    out.write("""
;; -- equal --
    mov rcx, 0
    mov rdx, 1
    pop rax
    pop rbx
    cmp rax, rbx
    cmove rcx, rdx
    push rcx
                    """)
                elif op[0] == OP_DUMP:
                    out.write("""
;; -- dump --
    pop rdi
    call dump
                    """)
                elif op[0] == OP_IF:
                    assert len(op) >= 2, "`if` instruction does not have reference to the end of it's block. Please call crossrefernce_blocks() on the program before trying to compile it"
                    out.write(f"""
;; -- if --
    pop rax
    test rax, rax
    jz addr_{op[1]}
                    """)
                elif op[0] == OP_ELSE:
                    assert len(op) >= 2, "`else` instruction does not have reference to the end of it's block. Please call crossrefernce_blocks() on the program before trying to compile it"
                    out.write(f"""
;; -- else --
jmp addr_{op[1]}
addr_{ip}:
                    """)
                elif op[0] == OP_END:
                    assert len(op) >= 2, "`do` instruction does not have reference to the end of it's block. Please call crossrefernce_blocks() on the program before trying to compile it"
                    out.write(f"""
;; -- end --
jmp addr_{op[1]}
addr_{ip}:
                    """)
                elif op[0] == OP_DUP:
                    out.write(f"""
;; -- dup --
    pop rax
    push rax
    push rax
                    """)
                elif op[0] == OP_GREATER:
                    out.write("""
;; -- greater --
    mov rcx, 0
    mov rdx, 1
    pop rbx
    pop rax
    cmp rax, rbx
    cmovg rcx, rdx
    push rcx
                    """)
                elif op[0] == OP_LESS:
                    out.write("""
;; -- less --
    mov rcx, 0
    mov rdx, 1
    pop rax
    pop rbx
    cmp rax, rbx
    cmovg rcx, rdx
    push rcx
                    """)
                elif op[0] == OP_WHILE:
                    out.write(f"""
;; -- while --
addr_{ip}:
                    """)
                elif op[0] == OP_DO:
                    assert len(op) >= 2, "`do` instruction does not have reference to the end of it's block. Please call crossrefernce_blocks() on the program before trying to compile it"
                    out.write(f"""
;; -- do --
    pop rax
    test rax, rax
    jz addr_{op[1]}
                    """)
                else:
                    assert False, "unreachable"
##### END LOOP
            out.write("""
;; -- exit --
    mov rax, 0x3c
    mov rdi, 0
    syscall
            """)

is_comment = False
comment_row = 0
def parse_token_as_op(token):
    global is_comment
    global comment_row
    assert COUNT_OPS == 13, "Exhaustive handeling in parse_token_as_op"
    (file_path, row, col, token) = token
    # Comment handeling
    if is_comment and comment_row == row:
        return None
    else:
        is_comment == False
    if '//' in token:
        is_comment = True
        comment_row = row
        return None
    # Op handeling
    if token.isspace():
        return None
    ops = {
        '+'    : (OP_PLUS, ),
        '-'    : (OP_MINUS, ),
        '='    : (OP_EQUAL, ),
        '.'    : (OP_DUMP, ),
        '>'    : (OP_GREATER, ),
        '<'    : (OP_LESS, ),
        'if'   : (OP_IF, ),
        'do'   : (OP_DO, ),
        'dup'  : (OP_DUP, ),
        'end'  : (OP_END, ),
        'else' : (OP_ELSE, ),
        'while': (OP_WHILE, ),
    }
    if token in ops:
        return ops[token]
    try:
        return (OP_PUSH, int(token))
    except ValueError as err:
        print( "%s:%d:%d: %s" % (file_path, row, col, err) )
        exit(1)

def crossreference_block(program):
    stack = []
    for ip, op in enumerate(program):
        assert COUNT_OPS == 13, "Exhaustive handling of ops in crossreference_block. Keep in mind, not all of the ops need to be implemented here. Only those that form blocks"
        if op[0] == OP_IF:
            stack.append(ip)
        elif op[0] == OP_ELSE:
            if_else_ip = stack.pop()
            assert program[if_else_ip][0] == OP_IF, "`else` can only be used in `if` blocks for now"
            program[if_else_ip] = (OP_IF, ip)
            stack.append(ip)
        elif op[0] == OP_END:
            block_ip = stack.pop()
            if program[block_ip][0] == OP_IF or program[block_ip][0] == OP_ELSE:
                program[block_ip] = (program[block_ip][0], ip)
                program[ip] = (OP_END, ip)
            elif program[block_ip][0] == OP_DO:
                program[ip] = (OP_END, program[block_ip][1])
                program[block_ip] = (OP_DO, ip)
            else:
                assert False, "`end` can only be used with `if`, `else`, and `do` blocks for now"
        elif op[0] == OP_WHILE:
            stack.append(ip)
        elif op[0] == OP_DO:
            while_ip = stack.pop()
            program[ip] = (OP_DO, while_ip)
            stack.append(ip)
    return program

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
    return crossreference_block(
        list(
            filter(
                lambda x: not x == None,
                [parse_token_as_op(token) for token in lex_file(program_path)]
            )
        )
    )

def usage(program):
        print(f"""
Usage: {program} <SUBCOMMAND> <file> [EXTRA]
SUBCOMMANDS:
    - sim <file>  -- Simulate the program
    - com <file>  -- Compile the program
EXTRA:
    -r            -- run the compiled program
        """)

def call_cmd(cmd):
    print("[CMD]",cmd)
    code = subprocess.call(cmd.split(' '))
    if code != 0:
        print(f"[ERROR] Failed running '{cmd}'")
        exit(code)

def uncons(xs):
    return (xs[0], xs[1:])

if __name__ == '__main__':
    import sys
    import subprocess

    argv = sys.argv

    assert len(argv) >= 1, "No program"

    (program_name, argv) = uncons(argv)
    if len(argv) < 1:
        usage(program_name)
        print("ERROR: no subcomand provided")
        exit(1)

    (subcommand, argv) = uncons(argv)
    compiled = False

    if subcommand == 'sim' or subcommand == 'simulate':
        if len(argv) < 1:
            usage(program_name)
            print("ERROR: No input file for the simulation")
            exit(1)
        (program_path, argv) = uncons(argv)
        print("[INFO] Loading program from file", program_path)
        program = load_program_from_file(program_path)
        print("[INFO] Simulating program")
        simulate_program(program)
    elif subcommand == 'com' or subcommand == 'compile':
        if len(argv) < 1:
            usage(program)
            print("ERROR: No input file for the compilation")
            exit(1)
        (program_path, argv) = uncons(argv)
        print("[INFO] Loading program from file", program_path)
        program = load_program_from_file(program_path)
        print("[INFO] Generating output.asm")
        compile_program(program, "./bin/output.asm")
        # TODO: check for successful compilation
        call_cmd("nasm -felf64 ./bin/output.asm")
        call_cmd("ld -o ./bin/output ./bin/output.o")
        call_cmd("rm -rf ./bin/output.o")
        compiled = True

        if len(argv) >= 1:
            for flag in argv:
                if flag == '-r':
                    if not compiled:
                        print("[ERROR] Program was not compiled, skipping '-r'")
                        continue
                    print('[INFO] Running compiled program')
                    call_cmd("./bin/output")
    else:
        usage(program_name)
        assert False, f"Unknown subcommand, {subcommand}"
