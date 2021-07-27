#! /usr/bin/python3

# (C) 2021 by folkert@vanheusden.com
# released under GPL v3.0

import getopt
import json
import math
import os
import sys
import time

core_file = None

trace_file = None

resolver = '/usr/bin/eu-addr2line'  # from the 'elfutils' package

human_friendly_backtrace = False

output_type = 'text'

exe_name = '?'

fh_out = sys.stdout

try:
    opts, args = getopt.getopt(sys.argv[1:], "c:t:r:bo:f:", ["core=", "trace=", "resolver=", "human-backtrace", "output-type=", "file="])
except getopt.GetoptError as err:
    print(err)
    sys.exit(1)

for o, a in opts:
    if o in ("-c", "--core"):
        core_file = a

    elif o in ("-t", "--trace"):
        trace_file = a

    elif o in ("-r", "--resolver"):
        resolver = a

    elif o in ("-o", "--output-type"):
        if a == 'html' or a == 'text':
            output_type = a

        else:
            assert False, "%s not understood for -o" % a

    elif o in ("-f", "--file"):
        fh_out = open(a, 'w')

    else:
        print('Invalid command line parameter: %s %s' % (o, a))
        print('-c --core      path to the core file')
        print('-t --trace     path to the trace file')
        print('-r --resolver  path to the symbol resolver (\'eu-addr2line\')')
        print('-o             \'html\' or \'text\'')
        print('-f             file to write report to, skip for stdout')
        assert False, "unhandled option"

check_by_itself = False  # only (when True) check for "locked by itself earlier"

#if not os.path.isfile(resolver):
#    print('Please install either %s or the "elfutils" package' % resolver)
#    sys.exit(1)

# also used for summary
resolver_cache = dict()

def resolve_addresses(core_file, chain):
    global resolver
    global resolver_cache

    if core_file == None:
        return

    chain_symbols = []

    addresses = chain.split(',')
    for a in addresses:
        if a == '(nil)' or a == '':
            break

        if a in resolver_cache:
            symbol = resolver_cache[a]

        else:
            symbol = os.popen('%s --core %s %s' % (resolver, core_file, a)).read().rstrip('\n')
            resolver_cache[a] = symbol

        if symbol == '??:0':  # could not resolve
            symbol = '%s:-1:-1' % a
            resolver_cache[a] = symbol

        chain_symbols.append(symbol)

    if len(chain_symbols):
        resolver_cache[chain] = chain_symbols

    return chain_symbols

def dump_stacktrace(symbols, ot):
    if ot == 'html':
        print('<table border=1>', file=fh_out)
        print('<tr><th>frame</th><th>symbol</th><th>line-nr</th><th></th></tr>', file=fh_out)

    else:
        print('\tsymbol\t\tline-nr', file=fh_out)

    p_file_name = None

    idx = 0

    for e in symbols:
        if e == '??:0':
            e += ':0'

        first_col = e.find(':')
        c_file_name = e[0:first_col]

        pars = e[first_col+1:].split(':')

        if p_file_name == c_file_name and human_friendly_backtrace == True:
            if ot == 'html':
                print('<tr><td>%d</d><td>%s</td><td>%s</td><td>%s</td></tr>' % (idx, '', pars[0], pars[1]), file=fh_out)

            else:
                print('\t%d\t%s\t%s\t%s' % (idx, ' ' * len(p_file_name), pars[0], pars[1]), file=fh_out)

        else:
            p_file_name = c_file_name

            while len(pars) < 2:
                pars.append('-')

            if ot == 'html':
                print('<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>' % (idx, c_file_name, pars[0], pars[1]), file=fh_out)

            else:
                print('\t%d\t%s' % e.replace(':', '\t'), file=fh_out)

        idx += 1

    if ot == 'html':
        print('</table>', file=fh_out)

state = dict()
before = dict()
by_who_m = dict()  # on mutex
by_who_t = dict()  # on tid
durations = dict()
l_durations = dict()
used_in_tid = dict()
deadlocks = []

locked = dict()
contended = dict()

any_records = False

start_ts = None
end_ts = None

PTHREAD_MUTEX_NORMAL = PTHREAD_MUTEX_RECURSIVE = PTHREAD_MUTEX_ERRORCHECK = None

def my_ctime(ts):
    dt = time.localtime(ts // 1000000)

    return '%04d-%02d-%02d %02d:%02d:%02d.%06d' % (dt.tm_year, dt.tm_mon, dt.tm_mday, dt.tm_hour, dt.tm_min, dt.tm_sec, ts % 1000000)

def emit_header():
    global start_ts
    global end_ts

    if output_type == 'html':
        print('<!DOCTYPE html>\n<html><head>', file=fh_out)
        print('<style>table{font-size:16px;font-family:"Trebuchet MS",Arial,Helvetica,sans-serif;border-collapse:collapse;border-spacing:0;width:100%}td,th{border:1px solid #ddd;text-align:left;padding:8px}tr:nth-child(even){background-color:#f2f2f2}th{padding-top:11px;padding-bottom:11px;background-color:#04aa6d;color:#fff}h1,h2,h3{font-family:monospace;margin-top:2.2em;}</style>', file=fh_out)
        print('<title>lock trace</title></head><body>', file=fh_out)
        print('<h1>LOCK TRACE</h1>', file=fh_out)
        print('<h2>table of contents</h2>', file=fh_out)
        print('<ul>', file=fh_out)
        print('<li><a href="#meta">meta data</a>', file=fh_out)
        print('<li><a href="#double">double locks/unlocks</a>', file=fh_out)
        print('<li><a href="#deadlocks">deadlocks</a>', file=fh_out)
        print('<li><a href="#slmut">still locked - grouped by mutex</a>', file=fh_out)
        print('<li><a href="#sltid">still locked - grouped by TID</a>', file=fh_out)
        print('<li><a href="#durations">locking durations</a>', file=fh_out)
        print('<li><a href="#lastmutexuse">where were mutexes used last</a>', file=fh_out)
        print('</ul>', file=fh_out)

    else:
        print(' +++ lock trace +++', file=fh_out)

    print('<a name="meta"></a><h2>META DATA</h2>', file=fh_out)
    print('<table><tr><th colspan=2>meta data</th></tr>', file=fh_out)
    print('<tr><td>executable:</td><td>%s</td></tr>' % exe_name, file=fh_out)
    print('<tr><td>PID:</td><td>%d</td></tr>' % pid, file=fh_out)
    print('<tr><td>host name:</td><td>%s</td></tr>' % hostname, file=fh_out)
    print('<tr><td>core file:</td><td>%s</td></tr>' % core_file, file=fh_out)
    print('<tr><td>trace file:</td><td>%s</td></tr>' % trace_file, file=fh_out)
    took = (end_ts - start_ts) / 1000000
    n_per_sec = n_records / took
    print('<tr><td># trace records:</td><td>%s (%.2f%%, %.2f%%/s)</td></tr>' % (n_records, n_records * 100.0 / n_records_max, n_per_sec * 100.0 / n_records_max), file=fh_out)
    print('<tr><td>fork warning:</td><td>%s</td></tr>' % fork_warning, file=fh_out)
    print('<tr><td># cores:</td><td>%s</td></tr>' % n_procs, file=fh_out)
    print('<tr><td>started at:</td><td>%d (%s)</td></tr>' % (start_ts, my_ctime(int(start_ts))), file=fh_out)
    print('<tr><td>stopped at:</td><td>%d (%s)</td></tr>' % (end_ts, my_ctime(int(end_ts))), file=fh_out)
    print('<tr><td>took:</td><td>%fs</td></tr>' % took, file=fh_out)
    print('</table>', file=fh_out)

    if output_type == 'html':
        print('<a name="double"></a><h2>DOUBLE LOCKS/UNLOCKS</h2>', file=fh_out)
        print('<ul>', file=fh_out)

    else:
        print(' *** DOUBLE LOCKS/UNLOCKS ***', file=fh_out)
        print('', file=fh_out)

def mutex_kind_to_str(mk):
    global PTHREAD_MUTEX_NORMAL
    global PTHREAD_MUTEX_RECURSIVE
    global PTHREAD_MUTEX_ERRORCHECK

    if mk == PTHREAD_MUTEX_NORMAL:
        return 'normal'

    if mk == PTHREAD_MUTEX_RECURSIVE:
        return 'recursive'

    if mk == PTHREAD_MUTEX_ERRORCHECK:
        return 'errorcheck'

    return '? %s ?' % mk

if trace_file:
    fh = open(trace_file)

while True:
    if trace_file:
        line = fh.readline()

    else:
        line = sys.stdin.readline()

    if not line:
        break

    j = json.loads(line)

    if j['type'] == 'meta' and 'mutex_type_normal' in j:
        PTHREAD_MUTEX_NORMAL = j['mutex_type_normal']

    elif j['type'] == 'meta' and 'n_records' in j:
        n_records = j['n_records']

    elif j['type'] == 'meta' and 'n_records_max' in j:
        n_records_max = j['n_records_max']

    elif j['type'] == 'meta' and 'mutex_type_recursive' in j:
        PTHREAD_MUTEX_RECURSIVE = j['mutex_type_recursive']

    elif j['type'] == 'meta' and 'mutex_type_errorcheck' in j:
        PTHREAD_MUTEX_ERRORCHEK = j['mutex_type_errorcheck']

    elif j['type'] == 'meta' and 'start_ts' in j:
        start_ts = j['start_ts']

    elif j['type'] == 'meta' and 'end_ts' in j:
        end_ts = j['end_ts']

    elif j['type'] == 'meta' and 'exe_name' in j:
        exe_name = j['exe_name']

    elif j['type'] == 'meta' and 'fork_warning' in j:
        fork_warning = j['fork_warning']

    elif j['type'] == 'meta' and 'hostname' in j:
        hostname = j['hostname']

    elif j['type'] == 'meta' and 'n_procs' in j:
        n_procs = j['n_procs']

    elif j['type'] == 'meta' and 'pid' in j:
        pid = j['pid']

    elif j['type'] == 'data' and j['action'] == 'lock':
        resolve_addresses(core_file, j['caller'])

        # cannot use 'durations' in case unlocks are performed more often than locks
        if not j['lock'] in l_durations:
            l_durations[j['lock']] = [ 0, 0 ]

        l_durations[j['lock']][0] += 1  # n
        l_durations[j['lock']][1] += j['lock_took']  # n

        if not (j['lock'] in state and (check_by_itself == False or (check_by_itself == True and state[j['lock']][2] == j['tid']))):
            state[j['lock']] = j

        if j['lock'] in locked:
            locked[j['lock']] += 1

        else:
            locked[j['lock']] = 1

        if locked[j['lock']] > 1:
            if j['lock'] in contended:
                contended[j['lock']] += 1

            else:
                contended[j['lock']] = 1

        if not j['lock'] in by_who_m:
            by_who_m[j['lock']] = dict()

        by_who_m[j['lock']][j['tid']] = j

        if not j['lock'] in used_in_tid:
            used_in_tid[j['lock']] = set()

        used_in_tid[j['lock']].add('%d (%s)' % (j['tid'], j['thread_name']))

        if j['tid'] in by_who_t and j['lock'] in by_who_t[j['tid']]:
                if output_type == 'html':
                    print('<h3>Double lock</h3>', file=fh_out)
                    print('<h4>current</h3>', file=fh_out)
                    print('<p>index: %s, mutex: %016x, tid: %s, thread name: %s, count: %s, owner: %s, kind: %s</p>' % (j['t'], j['lock'], j['tid'], j['thread_name'], j['mutex_count'], j['mutex_owner'], mutex_kind_to_str(j['mutex_kind'])), file=fh_out)
                else:
                    print('Double lock: ', j['t'], j['lock'], j['tid'], j['thread_name'], file=fh_out)

                dump_stacktrace(resolve_addresses(core_file, j['caller']), output_type)

                if output_type != 'html':
                    print('', file=fh_out)

                old_j = by_who_t[j['tid']][j['lock']]
                if output_type == 'html':
                    print('<h4>previous</h3>', file=fh_out)
                    print('<p>index: %s, tid: %s, thread name: %s, count: %s, owner: %s, kind: %s</p>' % (old_j['t'], old_j['tid'], old_j['thread_name'], j['mutex_count'], j['mutex_owner'], mutex_kind_to_str(j['mutex_kind'])), file=fh_out)
                else:
                    print('\t', old_j['t'], old_j['tid'], file=fh_out)

                dump_stacktrace(resolve_addresses(core_file, old_j['caller']), output_type)

                if output_type != 'html':
                    print('', file=fh_out)
                    print('', file=fh_out)

                any_records = True

        if not j['tid'] in by_who_t:
            by_who_t[j['tid']] = dict()

        by_who_t[j['tid']][j['lock']] = j

    elif j['type'] == 'data' and j['action'] == 'unlock':
        resolve_addresses(core_file, j['caller'])

        if j['lock'] in state:
            before[j['lock']] = state[j['lock']]
            del state[j['lock']]

        if j['lock'] in locked:  # in case of unlock without lock
            locked[j['lock']] -= 1

            if locked[j['lock']] <= 0:  # '<' in case of double unlocks
                del locked[j['lock']]

        if j['lock'] in by_who_m:
            if j['tid'] in by_who_m[j['lock']]:
                took = int(j['timestamp']) - int(by_who_m[j['lock']][j['tid']]['timestamp'])  # in s

                if not j['lock'] in durations:
                    durations[j['lock']] = [ 0, 0, 0, j['caller'], (j['t'], j['timestamp']), (0, 0), [] ]  # remember the first callback, usage

                durations[j['lock']][0] += 1  # n
                durations[j['lock']][1] += took  # avg
                durations[j['lock']][2] += took * took  # sd
                durations[j['lock']][5] = (j['t'], j['timestamp'])  # latest usage
                durations[j['lock']][6].append(float(took))  # median

                del by_who_m[j['lock']][j['tid']]

            else:
                if output_type == 'html':
                    print('<h3>Invalid unlock</h3>', file=fh_out)
                    print('<p>index: %s, mutex: %016x, tid: %s, thread_name: %s, count: %s, owner: %s, kind: %s</p>' % (j['t'], j['lock'], j['tid'], j['thread_name'], j['mutex_count'], j['mutex_owner'], mutex_kind_to_str(j['mutex_kind'])), file=fh_out)
                else:
                    print('Invalid unlock: ', j['t'], j['lock'], j['tid'], j['thread_name'], j['mutex_count'], j['mutex_owner'], mutex_kind_to_str(j['mutex_kind']), file=fh_out)

                dump_stacktrace(resolve_addresses(core_file, j['caller']), output_type)

                if output_type != 'html':
                    print('', file=fh_out)
                    print('', file=fh_out)

                any_records = True

        if j['tid'] in by_who_t:
            if j['lock'] in by_who_t[j['tid']]:
                del by_who_t[j['tid']][j['lock']]

    elif j['type'] == 'marker':
        emit_header()

    elif j['type'] == 'data' and j['action'] == 'tclean':  # forget a thread
        purge = []

        for s in state:
            if state[s][2] == j['tid']:
                purge.append(s)

        for p in purge:
            before[p] = state[p]
            del state[p]

    elif j['type'] == 'data' and j['action'] == 'deadlock':  # deadlock
        deadlocks.append(j)

    else:
        print('Unknown record: %s' % j)
        sys.exit(1)

if not any_records:
    print('<li>---', file=fh_out)

if output_type == 'html':
    print('</ul>', file=fh_out)

else:
    print('', file=fh_out)
    print('', file=fh_out)

def pp_record(j, end_ts, ot):
    since_ts = int(j['timestamp'])
    since = my_ctime(since_ts)

    if not end_ts:
        end_ts = since_ts - 1

    duration = (end_ts - since_ts) / 1000000.0

    rc = 'index: %s, mutex: %016x, tid: %s, name: %s, since: %s (%s), locked for %.6fs, count: %s, owner: %s, kind: %s' % (j['t'], j['lock'], j['tid'], j['thread_name'], j['timestamp'], since, duration, j['mutex_count'], j['mutex_owner'], mutex_kind_to_str(j['mutex_kind']))

    if ot == 'html':
        return '<li>%s</li>' % rc

    return rc

if output_type == 'html':
    print('<a name="deadlocks"></a><h2>DEADLOCKS</h2>', file=fh_out)
    print('<ul>', file=fh_out)

else:
    print(' *** DEADLOCKS ***', file=fh_out)
    print('', file=fh_out)

any_dl = False

for d in range(0, len(deadlocks)):
    print(pp_record(deadlocks[d], end_ts, output_type), file=fh_out)

    if output_type == 'html':
        print('<br>', file=fh_out)

    else:
        print('', file=fh_out)

    dump_stacktrace(resolve_addresses(core_file, deadlocks[d]['caller']), output_type)

    if output_type == 'html':
        print('<br>', file=fh_out)

    else:
        print('', file=fh_out)
        print('', file=fh_out)

    any_dl = True

if output_type == 'html':
    if not any_dl:
        print('<li>---', file=fh_out)

    print('</ul>', file=fh_out)

else:
    print('', file=fh_out)

if output_type == 'html':
    print('<a name="slmut"></a><h2>STILL LOCKED (grouped by mutex)</h2>', file=fh_out)
    print('<ul>', file=fh_out)

else:
    print(' *** STILL LOCKED (by mutex) ***', file=fh_out)
    print('', file=fh_out)

any_slm = False

for bw in by_who_m:
    if len(by_who_m[bw]) > 0:
        for ri in by_who_m[bw]:
            r = by_who_m[bw][ri]

            print(pp_record(r, end_ts, output_type), file=fh_out)

            if output_type == 'html':
                print('<br>', file=fh_out)

            else:
                print('', file=fh_out)

            dump_stacktrace(resolve_addresses(core_file, j['caller']), output_type)

            if output_type == 'html':
                print('<br>', file=fh_out)

            else:
                print('', file=fh_out)
                print('', file=fh_out)

            any_slm = True

if output_type == 'html':
    if not any_slm:
        print('<li>---', file=fh_out)

    print('</ul>', file=fh_out)

else:
    print('', file=fh_out)

if output_type == 'html':
    print('<a name="sltid"></a><h2>STILL LOCKED (grouped by TID)</h2>', file=fh_out)
    print('<ul>', file=fh_out)

else:
    print(' *** STILL LOCKED (by TID) ***', file=fh_out)
    print('', file=fh_out)

any_slt = False

for bw in by_who_t:
    if len(by_who_t[bw]) > 0:
        for ri in by_who_t[bw]:
            r = by_who_t[bw][ri]

            print(pp_record(r, end_ts, output_type), file=fh_out)

            if output_type == 'html':
                print('<br>', file=fh_out)

            else:
                print('', file=fh_out)

            dump_stacktrace(resolve_addresses(core_file, j['caller']), output_type)

            if output_type == 'html':
                print('<br>', file=fh_out)

            else:
                print('', file=fh_out)
                print('', file=fh_out)

            any_slt = True

if output_type == 'html':
    if not any_slt:
        print('<li>---', file=fh_out)

    print('</ul>', file=fh_out)

else:
    print('', file=fh_out)

if output_type == 'html':
    print('<a name="lastmutexuse"></a><h2>MUTEX USED LOCATIONS</h2>', file=fh_out)

else:
    print(' *** MUTEX USED LOCATIONS ***', file=fh_out)
    print('', file=fh_out)

temp = state
temp.update(before)

for r in temp:
    if output_type == 'html':
        print('<h3>%016x</h3>' % temp[r]['lock'], file=fh_out)
        print('<p>%s</p>' % pp_record(temp[r], end_ts, 'text'), file=fh_out)

    else:
        print(j['lock'], file=fh_out)
        print(pp_record(temp[r], end_ts, 'text'), file=fh_out)

    dump_stacktrace(resolve_addresses(core_file, temp[r]['caller']), output_type)

    print('<p>Threads (by TID) mutex seen in: %s</p>' % ', '.join(sorted(used_in_tid[j['lock']])), file=fh_out)

if output_type == 'html':
    print('<a name="durations"></a><h2>LOCKING DURATIONS</h2>', file=fh_out)

else:
    print(' *** LOCKING DURATIONS ***', file=fh_out)
    print('', file=fh_out)

for d in durations:
    n = durations[d][0]
    avg = durations[d][1] / n
    sd = math.sqrt((durations[d][2] / n) - math.pow(avg, 2.0))

    if output_type == 'html':
        print('<h3>mutex: %016x</h3>' % d, file=fh_out)
    else:
        print(d, file=fh_out)

    if output_type == 'html':
        print('<table><tr><th>what</th><th>value</th></tr>', file=fh_out)
        print('<tr><td># locks/unlocks:</td><td>%d</td></tr>' % n, file=fh_out)

        if d in contended:
            print('<tr><td>contended:</td><td>%.2f%% (%d)</td></tr>' % (contended[d] * 100.0 / n, contended[d]), file=fh_out)

        if d in l_durations and l_durations[d][0]:
            lock_took = l_durations[d][1] / l_durations[d][0]
            print('<tr><td>average time to take lock:</td><td>%.1fus</td></tr>' % lock_took, file=fh_out)

        print('<tr><td>total time:</td><td>%.1fus</td></tr>' % sum(durations[d][6]), file=fh_out)
        print('<tr><td>average:</td><td>%.6fus</td></tr>' % avg, file=fh_out)
        print('<tr><td>standard deviation:</td><td>%.6fus</td></tr>' % sd, file=fh_out)
        sorted_list = sorted(durations[d][6])
        print('<tr><td>mininum:</td><td>%.2fus</td></tr>' % sorted_list[0], file=fh_out)
        print('<tr><td>median:</td><td>%.2fus</td></tr>' % sorted_list[len(sorted_list) // 2], file=fh_out)
        print('<tr><td>maximum:</td><td>%.2fus</td></tr>' % sorted_list[-1], file=fh_out)
        print('<tr><td>first unlock seen:</td><td>%s (index %s)</td></tr>' % (my_ctime(int(durations[d][4][1])), durations[d][4][0]), file=fh_out)
        print('<tr><td>last unlock seen:</td><td>%s (index %s)</td></tr>' % (my_ctime(int(durations[d][5][1])), durations[d][5][0]), file=fh_out)
        print('</table>', file=fh_out)

        # this can be implemented way smarter
        steps = (sorted_list[-1] - sorted_list[0]) / 10

        start = sorted_list[0]
        next = start + steps

        slots = []
        while start < sorted_list[-1]:
            cnt = 0

            for v in sorted_list:
                if v >= start:
                    if v >= next:
                        break

                    cnt += 1

            slots.append((start, cnt))

            start = next
            next += steps

        print('<p><br></p>', file=fh_out)

        print('<table><tr><th>range</th><th>count</th></tr>', file=fh_out)
        for s in slots:
            print('<tr><td>%.2f ... %.2f</td><td>%d</td></tr>' % (s[0], s[0] + steps, s[1]), file=fh_out)
        print('</table>', file=fh_out)

    else:
        print('\tn: %d, avg: %.6fus, sd: %.6fus</p>' % (n, avg, sd), file=fh_out)
        print('', file=fh_out)

if output_type != 'html':
    print('', file=fh_out)
    print('', file=fh_out)

if output_type == 'html':
    print('<p><br><br></p><hr><font size=-1>This <b>locktracer</b> is (C) 2021 by Folkert van Heusden &lt;mail@vanheusden.com&gt;</font></body></ht,l>', file=fh_out)

else:
    print('This locktracer is (C) 2021 by Folkert van Heusden <mail@vanheusden.com>', file=fh_out)

fh_out.close()
