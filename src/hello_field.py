#!/usr/bin/python
#
# This is a Hello World example that formats output as fields.

from bcc import BPF
from bcc.utils import printb

# define BPF program
prog = """
int hello(void *ctx) {
    bpf_trace_printk("Hello, World!\\n");//デバッグ用でタイムスタンプなどの情報と共に、引数に渡したものをtrace_pipeへ送る
    return 0;
}
"""

# load BPF program
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")#アタッチを行う。eventにアタッチする場所を指定し、fn_nameにはアタッチする関数を指定する
b.trace_print()