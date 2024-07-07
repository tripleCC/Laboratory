# Copyright (c) (2019,2020) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

class symbol(str): pass
class ref(str): pass
class sizeof(str): pass
class uint64(int): pass


def genexpr(expr):
    if expr is None:
        return 'NULL'
    elif isinstance(expr, symbol):
        return expr
    elif isinstance(expr, ref):
        return '&{}'.format(expr)
    elif isinstance(expr, sizeof):
        return 'sizeof({})'.format(expr)
    elif isinstance(expr, str):
        return '"{}"'.format(expr)
    elif isinstance(expr, (bytearray, bytes)):
        return '{{ {} }}'.format(', '.join(['0x{:02x}'.format(b) for b in expr]))
    elif isinstance(expr, bool):
        return str(expr).lower()
    elif isinstance(expr, uint64):
        return '{}ULL'.format(expr)
    elif isinstance(expr, (int, float)):
        return str(expr)
    elif isinstance(expr, tuple):
        return '({}){}'.format(expr[0], genexpr(expr[1]))
    elif isinstance(expr, list):
        items = [genexpr(e) for e in expr]
        return '{{ {} }}'.format(', '.join(items))
    elif isinstance(expr, dict):
        fields = []
        for k, v in expr.items():
            fields.append('.{} = {}'.format(k, genexpr(v)))
        return '{{ {} }}'.format(', '.join(fields))
    else:
        raise 'Unexpected expr'


def codegen_gendecl(typefmt, sym, expr):
    decl = typefmt.format(sym)
    return sym, 'static const {} = {};'.format(decl, genexpr(expr))


class CodeGenerator:
    def __init__(self, symid=0):
        self.syms = []
        self.decls = []
        self.symid = symid

    def gensym(self, name):
        self.symid += 1
        return symbol('{}_{}'.format(name, self.symid))

    def genexpr(self, expr):
        return genexpr(expr)

    def gendecl(self, typefmt, name, expr, const=True):
        if const:
            qual = 'static const'
        else:
            qual = 'static'

        if isinstance(name, symbol):
            sym = name
        else:
            sym = self.gensym(name)

        decl = '{} {} = {};'.format(qual,
                                    typefmt.format(sym),
                                    self.genexpr(expr))
        self.syms.append(sym)
        self.decls.append(decl)
        return sym
