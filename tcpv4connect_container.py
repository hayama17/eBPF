#!/usr/bin/python3

from bcc import BPF
from bcc.utils import printb
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/sched.h>
#include <linux/utsname.h>
#include <linux/pid_namespace.h>
struct data_t{//パケットにまつわるデータについての構造体
    u32 pid;//PIDについてのunsigned int型の変数
    char comm[TASK_COMM_LEN];//コマンドについてのキャラ型の変数
    char nodename[16];
    u32 saddr;//送信アドレスについてのunsigned int型の変数
    u32 daddr;//受信アドレスについてのunsigned int型の変数
    u16 dport;//受信アドレスについてのunsigned short型の変数
};

// create map
BPF_HASH(socklist, u32, struct sock *);//ハッシュマップの作成(名前=socklist,キーの型=u32,キーに対応する値の型=struct sock )
//struct sockとはソケットをネットワーク層で表現した時の構造体
BPF_PERF_OUTPUT(events);//イベントが発生した場合、自分達で自由にデータを送信する際に使用する
//bpf_trace_printk("text")は文字列限定だけど、BPF_PERF_OUTPUT(events)は構造体でもポインタでも送れる

//HASHを使うときはアドレス=ポインタで表現出来るように渡さないといけない

// kprobe function
int tcp_connect(struct pt_regs *ctx, struct sock *sock){//tcpが通信する際にシステムコールが呼ばれた時に作動
    u32 pid = bpf_get_current_pid_tgid();//pidを取得する
    //実際は64ビットが返り値であるだが、
    //上位32bitスレッドID
    //下位32bitプロセスID
    //になっていてu32型へ代入する時上位32bitは破棄される
    socklist.update(&pid, &sock);//pidのアドレスとソケットのアドレスをマップに保存する
    return 0;
}

// kretprobe function
int tcp_connect_ret(struct pt_regs *ctx){//tcpの通信するシステムコールが呼び出され処理した後実行
    u32 pid = bpf_get_current_pid_tgid();//pidを取得
    struct sock **sock, *sockp;
    struct data_t data = {};
    sock = socklist.lookup(&pid);//pidのアドレスがsocklistのキーに入っているか探索、キーに対応する値(ソケットのアドレス)のポインタを返す
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();//task_struct構造体を取得
    struct pid_namespace *pidns = (struct pid_namespace *)task->nsproxy->pid_ns_for_children;
    struct uts_namespace *uts = (struct uts_namespace *)task->nsproxy->uts_ns;
    /* 
        task_struct構造体とは、プロセスが使用しているメモリーやファイル，ソケット，シグナルなどの情報を管理する構造体
        今回はtask_struct構造体のnsproxyを使い名前空間に関する構造体を取得する
        UTS:ホスト名、ドメイン名、コンテナID(大体そうみたい)
        PIDns:プロセスのネームスペース
    */ 
    if(sock == 0||pidns->level == 0 ){//無かったorネームスペースの深さが0(ホストプロセス)だからreturn
        return 0;
    }
    sockp = *sock;//pidに対応するソケットの構造体のアドレスを代入される
    data.pid = pid;//data.pidにpidを代入
    bpf_get_current_comm(&data.comm, sizeof(data.comm));//第1引数のアドレスにプログラム名をコピーしてくれる。
    bpf_probe_read(&data.nodename,sizeof(data.nodename),(void *)uts->name.nodename );//第1引数に値を挿入できる
    data.saddr = sockp->__sk_common.skc_rcv_saddr;//アドレスだから参照の->で
    data.daddr = sockp->__sk_common.skc_daddr;
    u16 dport = sockp->__sk_common.skc_dport;
    data.dport = ntohs(dport);
    events.perf_submit(ctx, &data, sizeof(data));//自分達が送信したいデータのアドレス(アスタリスクが付くと実体になる状態)とデータのサイズを引数にする
    socklist.delete(&pid);
    return 0;
}
"""
# u32で送られてくるのを`0.0.0.0`みたいな読みやすいものにする
def ntoa(addr):
    ipaddr = b''
    for n in range(0, 4):
        ipaddr = ipaddr + str(addr & 0xff).encode()
        if (n != 3):
            ipaddr = ipaddr + b'.'
        addr = addr >> 8
    return ipaddr

def test(addr):
    bytes =[]
    bytes.append(addr & 0xff)
    bytes.append(addr>>8 & 0xff)
    bytes.append(addr>>16 & 0xff)
    bytes.append(addr>>24 & 0xff)

    a = str(bytes[0])+"."+str(bytes[1])+"."+str(bytes[2])+"."+str(bytes[3])
    return a.encode()

# 出力用の関数
def get_print_event(b: BPF):
    def print_event(cpu, data, size):
        event = b["events"].event(data)
        printb(b"%-6d %-16s %-16s %-16s %-16d %-16s" % (
            event.pid, event.comm, test(event.saddr), ntoa(event.daddr), event.dport,event.nodename))

    return print_event


b = BPF(text=bpf_text)
# プログラムのアタッチ
b.attach_kprobe(event='tcp_v4_connect', fn_name="tcp_connect")
b.attach_kretprobe(event='tcp_v4_connect', fn_name="tcp_connect_ret")


b["events"].open_perf_buffer(get_print_event(b))

print("%-6s %-16s %-16s %-16s %-16s %-16s" % (
        "PID","COMMAND", "S-IPADDR", "D-IPADDR", "DPORT","CONTAINER ID"))
while 1:
   try:
      b.perf_buffer_poll()
   except KeyboardInterrupt:
      exit()