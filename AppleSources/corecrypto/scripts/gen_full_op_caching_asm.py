#!/usr/bin/env python3
#
# Copyright (c) (2023) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

import datetime
import argparse
import math
import sys
import os

OP_REGS = ['r3', 'r4', 'r5', 'r6', 'r7', 'r8']
IM_REGS = ['r9', 'r10', 'r11', 'r12']

def errprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

class OperandRegisters(object):
    def __init__(self, regs):
        self.available = regs
        self.assigned = {}

    def key(self, name, limb):
        return name + str(limb)

    def get(self, name, limb, assume_assigned=False):
        newly_assigned = False
        k = self.key(name, limb)

        if not (k in self.assigned):
            self.assigned[k] = self.available.pop(0)
            newly_assigned = True
            assert not assume_assigned

        return (self.assigned[k], newly_assigned)

    def get_assigned(self, name, limb):
        return self.get(name, limb, True)[0]

    def release(self, name, limb):
        k = self.key(name, limb)

        if k in self.assigned:
            self.available.append(self.assigned[k])
            del self.assigned[k]

class IntermediateRegisters(object):
    def __init__(self, regs):
        self.regs = regs

    def lo(self):
        return self.regs[0]

    def hi(self, i):
        return self.regs[i]

    def rotate(self):
        self.regs = self.regs[1:] + self.regs[:1]

class RowGeneratorState(object):
    def __init__(self, n, e, op_regs, im_regs):
        self.n = n
        self.e = e

        self.op_regs = op_regs
        self.im_regs = im_regs

        self.cols_with_values = set()

    def init(self, a):
        self.b = 0

        # First row could be a partial one.
        if i == 0:
            self.a = (self.num_rows() - 1) * self.e
            self.max_b = self.n - self.a - 1
        else:
            self.a = self.e * (i - 1)
            self.max_b = self.n - 1

        # If there's a partial row, the second one might be shorter.
        if i == 1:
            self.max_a = self.n - self.e * (self.num_rows() - 2) - 1
        else:
            self.max_a = min(self.n - 1, self.a + 2 * self.e - 1)

        self.prev_width = 1

    def col_has_value(self, col):
        return col in self.cols_with_values

    def num_rows(self):
        return math.ceil(self.n / self.e)

    # Width is the number of multiplications in the current column.
    def get_width(self):
        if self.b == 0:
            width = (self.a % self.e) + 1
        elif self.a == self.max_a:
            width = min(self.e, self.max_b + 1 - self.b)
        else:
            width = self.e

        return width

def release_non_overlapping_op_regs(state):
    # We start at A[a], any operand register A[0:a] can be released.
    for ai in range(0, state.a):
        state.op_regs.release('a', ai)

    # We start at A[a], any operand register A[a+e:] can be released.
    for ai in range(state.a + state.e, state.n):
        state.op_regs.release('a', ai)

    # We start a B[0], any operand register B[e:] can be released.
    for bi in range(state.e, state.n):
        state.op_regs.release('b', bi)

def print_group(lines):
    if len(lines) > 0:
        print('\n' + '\n'.join(lines))

def print_clear_registers(state, col):
    cregs = []

    # Warmup.
    if state.b == 0 and state.get_width() == 1:
        if state.col_has_value(col):
            cregs = [state.im_regs.lo()]
    else:
        first_im_reg = state.prev_width
        last_im_reg = state.get_width()

        if not state.col_has_value(col):
            last_im_reg += 1

        # Clear registers, if needed.
        for i in range(first_im_reg, last_im_reg):
            cregs.append(state.im_regs.hi(i))

    print_group(['mov %s, #0' % cr for cr in cregs])

def get_operands(state):
    for i in range(0, state.get_width()):
        yield (i, state.a - i, state.b + i)

def print_loads(state, col):
    loads = []

    # Load intermediate values from stack, if needed.
    if state.col_has_value(col):
        loads.append((state.im_regs.hi(state.get_width()), 'sp', col))

    # Load operands.
    for (_, ai, bi) in get_operands(state):
        (reg_a, load_a) = state.op_regs.get('a', ai)
        if load_a:
            loads.append((reg_a, 'r1', ai))

        (reg_b, load_b) = state.op_regs.get('b', bi)
        if load_b:
            loads.append((reg_b, 'r2', bi))

    print_group(['ldr %s, [%s, #(%d*4)]' % l for l in loads])

def print_multiplications(state, col):
    ins = 'umaal'

    # First multiplication in a column? Use umull.
    if state.b == 0 and state.get_width() == 1 and not state.col_has_value(col):
        ins = 'umull'

    # Multiply.
    for (i, ai, bi) in get_operands(state):
        reg_a = state.op_regs.get_assigned('a', ai)
        reg_b = state.op_regs.get_assigned('b', bi)

        print('\n// A%d * B%d' % (ai, bi))
        print('%s %s, %s, %s, %s' % (ins, state.im_regs.lo(), state.im_regs.hi(i + 1), reg_a, reg_b))

def print_row(state):
    # Release all operand registers that don't overlap with
    # the starting position. We can't reuse any of them.
    release_non_overlapping_op_regs(state)

    for col in range(state.a, state.n * 2 - 1):
        # Invariant.
        assert state.a < state.n and state.b < state.n

        # Clear registers for umaal.
        print_clear_registers(state, col)

        # Load operands and intermediate values.
        print_loads(state, col)

        # Multiply operands.
        print_multiplications(state, col)

        # Store the current limb on the stack.
        print('\nstr %s, [sp, #(%d*4)]' % (state.im_regs.lo(), col))

        # The column has an intermediate value (now).
        state.cols_with_values.add(col)

        # im_regs <<< 1
        state.im_regs.rotate()

        state.prev_width = state.get_width()

        # End of row.
        if state.a == state.max_a and state.b == state.max_b:
            state.cols_with_values.add(col + 1)
            print('str %s, [sp, #(%d*4)]' % (state.im_regs.lo(), col + 1))
            break

        if state.b == 0 and state.get_width() < state.e and col < state.n - 1:
            # Warmup.
            state.a += 1
        elif state.a == state.max_a and state.b + state.get_width() == state.n:
            # Cooldown.
            state.b += 1
        elif state.a == state.n - 1 and state.max_b < state.e and col >= state.n - 1:
            # Cooldown (initial row).
            state.b += 1
        elif (state.a + state.b - state.n + 1) in range(0, state.get_width()) and state.a < state.max_a:
            # Upwards
            state.op_regs.release('a', state.a - state.get_width() + 1)
            state.a += 1
        else:
            # Downwards.
            state.op_regs.release('b', state.b)
            state.b += 1

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--bits", help = "Number of bits for a single operand.", default = None)

    args = parser.parse_args()
    if not args.bits:
        parser.print_help()
        sys.exit(1)

    # Number of bits for a full operand.
    B = int(args.bits)

    # Number of limbs (bits divided by word size).
    N = B // 32

    # The max. "width" of the row.
    E = 3

    # 2 * E operand registers required.
    assert len(OP_REGS) == 2 * E

    # E + 1 intermediate value registers required.
    assert len(IM_REGS) == E + 1

    print('''/* Copyright (c) (%s) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

// This file is auto-generated. Please don't modify it.
''' % datetime.datetime.now().year)

    print('// Store the %d-bit product on the stack.' % (B * 2))
    print('sub sp, #(%d*4)' % (N * 2))

    op_regs = OperandRegisters(OP_REGS)
    im_regs = IntermediateRegisters(IM_REGS)

    state = RowGeneratorState(N, E, op_regs, im_regs)
    for i in range(0, state.num_rows()):
        state.init(i)
        print_row(state)
