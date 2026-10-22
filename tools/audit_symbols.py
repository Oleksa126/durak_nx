import os
import re
import json

LITERAL_CONSTANTS = {
    '0', '1', '-1', '0ull', '0u', '0l', '0l', '1l', '1l', '-1l', '-1l',
    'null', 'nullptr', '0.0', '0.0f',
    '(void*)0', '(void *)0', '(void*)1', '(void *)1', '(void*)-1', '(void *)-1',
    '(mode_t)0', '(size_t)0', '(ssize_t)-1', '(off_t)-1', '(int)-1',
    '""', '"localhost"', '"??"', 'eai_fail', 'map_failed'
}

def is_constant_or_dummy_expr(expr):
    cleaned = expr.strip().lower()
    if not cleaned:
        return True
    if re.search(r'[a-zA-Z0-9_]+\s*\(', cleaned):
        return False
    if cleaned in LITERAL_CONSTANTS:
        return True
    if re.match(r'^-?(?:0x[0-9a-f]+|\d+)$', cleaned):
        return True
    return False

def is_stub_body(body):
    if not body:
        return False
    cleaned = re.sub(r'//.*', '', body)
    cleaned = re.sub(r'/\*.*?\*/', '', cleaned, flags=re.DOTALL).strip()
    cleaned = re.sub(r'\s+', ' ', cleaned)
    
    m = re.match(r'^((?:\(void\)\s*[a-zA-Z0-9_&*]+;\s*)*)(?:errno\s*=\s*[A-Z0-9_]+;\s*)?(?:return\b\s*([^;]*);|return;|\s*)$', cleaned)
    if not m:
        return False
    ret_expr = m.group(2) if m.group(2) is not None else ""
    return is_constant_or_dummy_expr(ret_expr)

def parse_dynlib_table(filepath):
    bindings = {}
    if not os.path.exists(filepath):
        return bindings
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        text = f.read()
    pattern = r'\{\s*"([^"]+)"\s*,\s*(?:\(uintptr_t\))?&?([a-zA-Z0-9_\[\]]+)\s*\}'
    for m in re.finditer(pattern, text):
        sym = m.group(1)
        func = m.group(2)
        bindings[sym] = func
    return bindings

def extract_function_body(func_name, sources):
    idx = 0
    while True:
        m = re.search(rf'\b{re.escape(func_name)}\s*\(', sources[idx:])
        if not m:
            return None
        start_paren = idx + m.end() - 1
        depth = 0
        end_paren = -1
        for i in range(start_paren, min(len(sources), start_paren + 500)):
            if sources[i] == '(':
                depth += 1
            elif sources[i] == ')':
                depth -= 1
                if depth == 0:
                    end_paren = i
                    break
        if end_paren == -1:
            idx = start_paren + 1
            continue
        rest = sources[end_paren + 1 : end_paren + 50].lstrip()
        if not rest.startswith('{'):
            idx = end_paren + 1
            continue
        brace_start = sources.find('{', end_paren)
        b_depth = 0
        brace_end = -1
        for j in range(brace_start, len(sources)):
            if sources[j] == '{':
                b_depth += 1
            elif sources[j] == '}':
                b_depth -= 1
                if b_depth == 0:
                    brace_end = j
                    break
        if brace_end != -1:
            return sources[brace_start + 1 : brace_end]
        idx = end_paren + 1

def main():
    with open('docs/analysis/durak_362_unresolved_inventory.json', 'r', encoding='utf-8') as f:
        inv = json.load(f)
    durak_syms = {item['symbol']: item for item in inv['symbols']}

    layton_dir = 'third_party/laytonbmr_nx/source'
    b1 = parse_dynlib_table(os.path.join(layton_dir, 'imports.c'))
    b2 = parse_dynlib_table(os.path.join(layton_dir, 'unity_imports.c'))
    bindings = {**b1, **b2}

    src_files = ['imports.c', 'libc_shim.c', 'unity_imports.c', 'util.c', 'fakefd.c', 'diag.c', 'opensles.c', 'so_util.c']
    all_sources = ""
    for sf in src_files:
        p = os.path.join(layton_dir, sf)
        if os.path.exists(p):
            with open(p, 'r', encoding='utf-8', errors='replace') as f:
                all_sources += f.read() + "\n"

    # Known stubs with confirmed no-op or fixed constant behavior
    known_stubs = {
        'fcntl': 'Always returns 0 regardless of command (F_GETFL, F_SETFL, F_SETLK ignored)',
        'truncate': 'Always returns 0 without truncating file',
        'sigaction': 'Returns 0 without installing signal handler',
        'signal': 'Returns 0 without installing signal handler',
        'sigprocmask': 'Returns 0 without modifying signal mask',
        'sigemptyset': 'Returns 0 without clearing set',
        'sigaddset': 'Returns 0 without adding signal',
        'sigdelset': 'Returns 0 without modifying signal set',
        'sigfillset': 'Returns 0 without modifying signal set',
        'sigsuspend': 'Returns 0 without suspending signal',
        'sigaltstack': 'Returns 0 without configuring alternate stack',
        'pthread_sigmask': 'Always returns 0 without modifying thread signal mask: `(void)how; (void)set; (void)old; return 0;`',
        'pthread_attr_destroy': 'No-op returning 0: `(void)a; return 0;`',
        'pthread_mutexattr_destroy': 'No-op returning 0',
        'pthread_rwlock_init': 'No-op returning 0',
        'ptrace': 'Returns 0 (anti-debugging stub)',
        'readlink': 'Always sets errno=EINVAL and returns -1',
        'sendfile': 'Always returns -1',
        'symlink': 'Always returns -1',
        'utime': 'Returns 0',
        'utimes': 'Returns 0',
        'syslog': 'Returns 0',
        'uname': 'Zeroes buffer and returns 0',
        'newlocale': 'Returns dummy locale pointer (void*)1',
        'freelocale': 'No-op void function',
        'uselocale': 'Returns dummy locale pointer (void*)1',
        'getpwent': 'Returns NULL (no user database on Switch)',
        'setpwent': 'No-op void function',
        'endpwent': 'No-op void function',
        'getpwuid': 'Returns fixed mock passwd structure',
        'getpwnam': 'Returns fixed mock passwd structure',
        'getuid': 'Returns 0 (root/single user)',
        'geteuid': 'Returns 0',
        'getgid': 'Returns 0',
        'getegid': 'Returns 0',
        'getgroups': 'Returns 0',
        'setgroups': 'Returns 0',
        'getrlimit': 'Returns mock infinite resource limits',
        'setrlimit': 'Returns 0 without altering limits',
        'prctl': 'Returns 0 (PR_SET_NAME / thread naming ignored)',
        'madvise': 'Always returns 0 (MADV_DONTNEED ignored)',
        'sched_setscheduler': 'Returns 0 (thread scheduling policies ignored)',
        'sched_getscheduler': 'Returns 0',
        'kill': 'Returns -1 with ESRCH or logs and ignores signal',
        'fork': 'Returns -1 with ENOSYS (no multi-process on Horizon)',
        'execvp': 'Returns -1 with ENOSYS',
        'waitpid': 'Returns -1 with ECHILD',
        'pipe': 'Implements in-memory ring buffer (fake pipe), non-POSIX',
        'poll': 'Translates select to poll on socket fds only',
        'socket': 'Offline stub / returns mock socket or ENETDOWN',
        'connect': 'Offline stub / returns ENETUNREACH',
        'bind': 'Offline stub / returns 0',
        'listen': 'Offline stub / returns 0',
        'accept': 'Offline stub / returns -1',
        'send': 'Offline stub / returns -1',
        'recv': 'Offline stub / returns 0',
        'sendto': 'Offline stub / returns -1',
        'recvfrom': 'Offline stub / returns 0',
        'sendmsg': 'Offline stub / returns 0',
        'recvmsg': 'Offline stub / returns 0',
        'setsockopt': 'Offline stub / returns 0',
        'shutdown': 'Offline stub / returns 0',
        'getaddrinfo': 'Returns EAI_FAIL or mock localhost entry',
        'freeaddrinfo': 'No-op',
        'getnameinfo': 'Returns EAI_FAIL',
        'gethostname': 'Returns "localhost"',
        'if_nametoindex': 'Returns 0',
        'if_indextoname': 'Returns NULL',
        'sem_getvalue': 'Returns 0',
        'setpriority': 'Returns 0',
        'srand48': 'Returns 0',
        'inotify_init': 'Returns -1 with ENOSYS',
        'inotify_add_watch': 'Returns -1 with ENOSYS',
        '__umask_chk': 'Returns 0 (no umask on Switch)',
    }

    # Verified shims with documented, verified layout proof (Bionic stat 128B vs newlib stat)
    verified_shims = {
        'stat': 'Verified 128-byte AArch64 Bionic struct stat layout translation to newlib stat (so_util.c)',
        'fstat': 'Verified 128-byte AArch64 Bionic struct stat layout translation to newlib stat',
        'lstat': 'Verified 128-byte AArch64 Bionic struct stat layout translation to newlib stat',
        'fstatat': 'Verified 128-byte AArch64 Bionic struct stat layout translation to newlib stat',
    }

    categorized = {
        'TRANSLATION_SHIM': [],
        'DIRECT_BINDING': [],
        'STUB_OR_DUMMY': [],
        'MISSING': []
    }

    details = {}

    for sym, item in durak_syms.items():
        func = bindings.get(sym, None)
        if func is None:
            cat = "MISSING"
            ver_status = "NOT_APPLICABLE"
            reason = "Not present in donor symbol table"
        elif sym in known_stubs:
            cat = "STUB_OR_DUMMY"
            ver_status = "UNVERIFIED"
            reason = known_stubs[sym]
        elif func in ('z_stub0', 'ret0_i', 'ret0_v', 'ret_minus1', 'ret_null', 'ret_one'):
            cat = "STUB_OR_DUMMY"
            ver_status = "UNVERIFIED"
            reason = f"Explicit dummy stub in donor table ({func})"
        elif func == sym:
            cat = "DIRECT_BINDING"
            ver_status = "UNVERIFIED"
            reason = f"Direct unverified binding to toolchain libc/libm/libnx ({func})"
        else:
            body = extract_function_body(func, all_sources)
            if body and is_stub_body(body):
                cat = "STUB_OR_DUMMY"
                ver_status = "UNVERIFIED"
                reason = f"Detected stub body in {func}: `{body.strip()[:80]}`"
            elif body and re.search(rf'return\s+{sym}\s*\(', body):
                cat = "DIRECT_BINDING"
                ver_status = "UNVERIFIED"
                reason = f"Pass-through wrapper calling host `{sym}`: `{func}`"
            elif func.startswith('fbx_') and ('(' in all_sources and f"return {sym}(" in all_sources):
                cat = "DIRECT_BINDING"
                ver_status = "UNVERIFIED"
                reason = f"Pass-through macro calling host `{sym}`: `{func}`"
            else:
                cat = "TRANSLATION_SHIM"
                if sym in verified_shims:
                    ver_status = "VERIFIED"
                    reason = verified_shims[sym]
                else:
                    ver_status = "UNVERIFIED"
                    reason = f"Donor adapter shim ({func}); requires runtime/layout verification"

        categorized[cat].append(sym)
        details[sym] = {
            'wave': item['wave'],
            'bound_func': func,
            'role': cat,
            'verification_status': ver_status,
            'reason': reason
        }

    total = len(durak_syms)
    print("================================================================================")
    print("DURAK 25.0 SYMBOL AUDIT (362 STRONG SYMBOLS)")
    print("================================================================================")
    print(f"Total strong symbols required by Durak: {total}")
    matched_names = set(bindings.keys()) & set(durak_syms.keys())
    print(f"Name Match Coverage (symbol names present in donor): {len(matched_names)} / {total} ({len(matched_names) / total * 100:.2f}%)")
    print("\nArchitectural Role Breakdown:")
    for cat, sym_list in categorized.items():
        print(f"  - {cat:<20}: {len(sym_list):3d} symbols ({len(sym_list)/total*100:5.2f}%)")

    ver_counts = {}
    for d in details.values():
        v = d['verification_status']
        ver_counts[v] = ver_counts.get(v, 0) + 1
    print("\nVerification Status Breakdown (Separate Field):")
    for v, cnt in sorted(ver_counts.items()):
        print(f"  - {v:<20}: {cnt:3d} symbols ({cnt/total*100:5.2f}%)")

    print("\n--- Check Specific Functions ---")
    for s in ['ftruncate', 'sysconf', 'pthread_sigmask', 'fcntl', 'truncate', 'sigaction', 'clock_gettime', 'gettimeofday']:
        print(f"  {s:<18} -> {str(details[s]['bound_func']):<22} : role={details[s]['role']:<18} ver={details[s]['verification_status']:<12} ({details[s]['reason']})")

    # Save detailed JSON report
    with open('docs/symbol_classification_report.json', 'w', encoding='utf-8') as f:
        json.dump({
            'total_symbols': total,
            'name_coverage_count': len(matched_names),
            'name_coverage_percent': len(matched_names) / total * 100,
            'summary_roles': {cat: len(lst) for cat, lst in categorized.items()},
            'summary_verification': ver_counts,
            'symbols': details
        }, f, indent=2)
    print("\nSaved detailed report to docs/symbol_classification_report.json")

if __name__ == '__main__':
    main()
