#!/usr/bin/env python
from sys import argv, stderr
from generator_cmp_wk import generate_cmp_wk
from generator_cmp import generate_cmp
try:
    fld_n = int(argv[1])
except (IndexError, ValueError):
    stderr.write("Usage: %s [field num]\n" % argv[0])
    exit(0)
const_wk_arr = "const tuple_cmp_wk_t tuple_compare_with_key_arr[%d] = {\n" % (1 << fld_n)
for k in range(1 << fld_n):
    cmp_type = ("{0:0%db}" % fld_n).format(k)[::-1].replace('0','n').replace('1','s')
    const_wk_arr += "\ttuple_compare_with_key_%s,\n" % cmp_type
    generate_cmp_wk(cmp_type)
    print("")
const_wk_arr += "};"

const_arr = "const tuple_cmp_t tuple_compare_arr[%d][%d] = {\n" % (fld_n + 1, 1 << fld_n)
for i in range(fld_n + 1):
    const_arr += "\t{\n";
    for k in range(1 << i):
        cmp_type = ("{0:0%db}" % i).format(k)[::-1].replace('0','n').replace('1','s')
        cmp_type = cmp_type if i != 0 else ""
        const_arr += "\t\ttuple_compare_%s,\n" % cmp_type
        generate_cmp(cmp_type)
        print("")
    const_arr += "\t},\n";
const_arr += "};"
print(const_wk_arr)
print(const_arr)
    
