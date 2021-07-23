#! /usr/bin/python3

# (C) 2021 by folkert@vanheusden.com
# released under GPL v3.0

import getopt
import math
import os
import sys
import time

core_file = None

trace_file = None

resolver = '/usr/bin/eu-addr2line'  # from the 'elfutils' package

human_friendly_backtrace = False

output_type = 'text'

try:
    opts, args = getopt.getopt(sys.argv[1:], "c:t:r:bo:", ["core=", "trace=", "resolver=", "human-backtrace", "output-type="])
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

    else:
        assert False, "unhandled option"

if output_type == 'html':
    print('<!DOCTYPE html>\n<html><head>')
    print('<style>table{font-size:16px;font-family:"Trebuchet MS",Arial,Helvetica,sans-serif;border-collapse:collapse;border-spacing:0;width:100%}td,th{border:1px solid #ddd;text-align:left;padding:8px}tr:nth-child(even){background-color:#f2f2f2}th{padding-top:11px;padding-bottom:11px;background-color:#04aa6d;color:#fff}h1,h2,h3{font-family:monospace;margin-top:2.2em;}</style>')
    print('<title>lock trace</title></head><body>')
    print('<h1>LOCK TRACE</h1>')

    print('<ul>')
    print('<li><a href="#double">double locks/unlocks</a>')
    print('<li><a href="#sumback">summary backtraces</a>')
    print('<li><a href="#sumsym">summary symbols</a>')
    print('<li><a href="#slmut">still locked - grouped by mutex</a>')
    print('<li><a href="#sltid">still locked - grouped by TID</a>')
    print('<li><a href="#durations">locking durations</a>')
    print('</ul>')

else:
    print(' +++ lock trace +++')

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

    if chain in resolver_cache:
        return resolver_cache[chain]

    else:
        chain_symbols = []

        addresses = chain.split(',')
        for a in addresses:
            if a == '(nil)' or a == '':
                break

            symbol = os.popen('%s --core %s %s' % (resolver, core_file, a)).read().rstrip('\n')

            chain_symbols.append(symbol)

        if len(chain_symbols):
            resolver_cache[chain] = chain_symbols

        return chain_symbols

def dump_stacktrace(symbols, ot):
    if ot == 'html':
        print('<table border=1>')
        print('<tr><th>frame</th><th>symbol</th><th>line-nr</th><th></th></tr>')

    else:
        print('\tsymbol\t\tline-nr')

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
                print('<tr><td>%d</d><td>%s</td><td>%s</td><td>%s</td></tr>' % (idx, '', pars[0], pars[1]))

            else:
                print('\t%d\t%s\t%s\t%s' % (idx, ' ' * len(p_file_name), pars[0], pars[1]))

        else:
            p_file_name = c_file_name

            while len(pars) < 2:
                pars.append('-')

            if ot == 'html':
                print('<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>' % (idx, c_file_name, pars[0], pars[1]))

            else:
                print('\t%d\t%s' % e.replace(':', '\t'))

        idx += 1

    if ot == 'html':
        print('</table>')

if trace_file:
    lines = open(trace_file).readlines()

else:
    lines = sys.stdin.readlines()

# t   mutex   tid action    callers timestamp   tid-name
records = [ l.split() for l in lines ]

state = dict()
before = dict()
by_who_m = dict()  # on mutex
by_who_t = dict()  # on tid
durations = dict()

if output_type == 'html':
    print('<a name="double"></a><h2>DOUBLE LOCKS/UNLOCKS</h2>')
    print('<ul>')

else:
    print(' *** DOUBLE LOCKS/UNLOCKS ***')
    print('')

any_records = False

for r in records:
    if r[3] == 'lock':
        resolve_addresses(core_file, r[4])

        if not (r[1] in state and (check_by_itself == False or (check_by_itself == True and state[r[1]][2] == r[2]))):
            state[r[1]] = r

        if not r[1] in by_who_m:
            by_who_m[r[1]] = dict()

        by_who_m[r[1]][r[2]] = r

        if r[2] in by_who_t and r[1] in by_who_t[r[2]]:
                if output_type == 'html':
                    print('<h3>Double lock</h3>')
                    print('<h4>current</h3>')
                    print('<p>index: %s, mutex: %s, tid: %s, thread name: %s</p>' % (r[0], r[1], r[2], r[6]))
                else:
                    print('Double lock: ', r[0], r[1], r[2], r[6])

                dump_stacktrace(resolve_addresses(core_file, r[4]), output_type)

                if output_type != 'html':
                    print('')

                old_r = by_who_t[r[2]][r[1]]
                if output_type == 'html':
                    print('<h4>previous</h3>')
                    print('<p>index: %s, tid: %s, thread name: %s</p>' % (old_r[0], old_r[2], old_r[6]))
                else:
                    print('\t', old_r[0], old_r[2])

                dump_stacktrace(resolve_addresses(core_file, old_r[4]), output_type)

                if output_type != 'html':
                    print('')
                    print('')

                any_records = True

        if not r[2] in by_who_t:
            by_who_t[r[2]] = dict()

        by_who_t[r[2]][r[1]] = r

    elif r[3] == 'unlock':
        resolve_addresses(core_file, r[4])

        if r[1] in state:
            before[r[1]] = state[r[1]]
            del state[r[1]]

        if r[1] in by_who_m:
            if r[2] in by_who_m[r[1]]:
                took = int(r[5]) - int(by_who_m[r[1]][r[2]][5])  # in s

                if not r[1] in durations:
                    durations[r[1]] = [ 0, 0, 0, r[4], (r[0], r[5]), (0, 0), [] ]  # remember the first callback, usage

                durations[r[1]][0] += 1  # n
                durations[r[1]][1] += took  # avg
                durations[r[1]][2] += took * took  # sd
                durations[r[1]][5] = (r[0], r[5])  # latest usage
                durations[r[1]][6].append(float(took))  # median

                del by_who_m[r[1]][r[2]]

            else:
                if output_type == 'html':
                    print('<h3>Invalid unlock</h3>')
                    print('<p>index: %s, mutex: %s, tid: %s, thread_name: %s</p>' % (r[0], r[1], r[2], r[6]))
                else:
                    print('Invalid unlock: ', r[0], r[1], r[2], r[6])

                dump_stacktrace(resolve_addresses(core_file, r[4]), output_type)

                if output_type != 'html':
                    print('')
                    print('')

                any_records = True

        if r[2] in by_who_t:
            if r[1] in by_who_t[r[2]]:
                del by_who_t[r[2]][r[1]]

    elif r[3] == 'action':  # header
        pass

    elif r[3] == 'tclean':  # forget a thread
        purge = []

        for s in state:
            if state[s][2] == state[s][2]:
                purge.append(s)

        for p in purge:
            before[p] = state[p]
            del state[p]

    else:
        print('Unknown action: %s' % r[4])
        sys.exit(1)

if not any_records:
    print('<li>---')

if output_type == 'html':
    print('</ul>')

else:
    print('')
    print('')

if output_type == 'html':
    print('<a name="sumback"></a><h2>SUMMARY BACKTRACES</h2>')
else:
    print(' *** SUMMARY BACKTRACES ***')
    print('')

for c in resolver_cache:
    if output_type == 'html':
        print('<h3>%s</h3>' % c.replace(',', ', '))

    else:
        print(c)

    dump_stacktrace(resolver_cache[c], output_type)

    if output_type != 'html':
        print('')

if output_type != 'html':
    print('')
    print('')

if output_type == 'html':
    print('<a name="sumsym"></a><h2>SUMMARY SYMBOLS</h2>')
    print('<table border=1>')
    print('<tr><th>path</th><th>line number</th><th></th></tr>')
else:
    print(' *** SUMMARY SYMBOLS ***')
    print('')

symbols = set()

for c in resolver_cache:
    for s in resolver_cache[c]:
        if not s in symbols:
            symbols.add(s)

for s in sorted(symbols):
    if output_type == 'html':
        parts = s.split(':')

        while len(parts) < 3:
            parts.append('-')

        print('<tr><td>%s</td><td>%s</td><td>%s</td></tr>' % (parts[0], parts[1], parts[2]))

    else:
        print(s)
        print('')

if output_type == 'html':
    print('</table>')

else:
    print('')

def my_ctime(ts):
    dt = time.localtime(ts // 1000000)

    return '%04d-%02d-%02d %02d:%02d:%02d.%06d' % (dt.tm_year, dt.tm_mon, dt.tm_mday, dt.tm_hour, dt.tm_min, dt.tm_sec, ts % 1000000)

def pp_record(r, ot):
    since = my_ctime(int(r[5]))

    rc = 'index: %s, mutex: %s, tid: %s, name: %s, since: %s (%s)' % (r[0], r[1], r[2], r[6], r[5], since)

    if ot == 'html':
        return '<li>%s</li>' % rc

    return rc

if output_type == 'html':
    print('<a name="slmut"></a><h2>STILL LOCKED (grouped by mutex)</h2>')
    print('<ul>')

else:
    print(' *** STILL LOCKED (by mutex) ***')
    print('')

any_slm = False

for bw in by_who_m:
    if len(by_who_m[bw]) > 0:
        for ri in by_who_m[bw]:
            r = by_who_m[bw][ri]

            print(pp_record(r, output_type))
            if output_type == 'html':
                print('<br>')
            else:
                print('')
            dump_stacktrace(resolve_addresses(core_file, r[4]), output_type)
            if output_type == 'html':
                print('<br>')
            else:
                print('')
                print('')

            any_slm = True

if output_type == 'html':
    if not any_slm:
        print('<li>---')

    print('</ul>')

else:
    print('')

if output_type == 'html':
    print('<a name="sltid"></a><h2>STILL LOCKED (grouped by TID)</h2>')
    print('<ul>')

else:
    print(' *** STILL LOCKED (by TID) ***')
    print('')

any_slt = False

for bw in by_who_t:
    if len(by_who_t[bw]) > 0:
        for ri in by_who_t[bw]:
            r = by_who_t[bw][ri]

            print(pp_record(r, output_type))
            if output_type == 'html':
                print('<br>')
            else:
                print('')
            dump_stacktrace(resolve_addresses(core_file, r[4]), output_type)
            if output_type == 'html':
                print('<br>')
            else:
                print('')
                print('')

            any_slt = True

if output_type == 'html':
    if not any_slt:
        print('<li>---')

    print('</ul>')

else:
    print('')

if output_type == 'html':
    print('<a name="durations"></a><h2>LOCKING DURATIONS</h2>')

else:
    print(' *** LOCKING DURATIONS ***')
    print('')

for d in durations:
    n = durations[d][0]
    avg = durations[d][1] / n
    sd = math.sqrt((durations[d][2] / n) - math.pow(avg, 2.0))

    if output_type == 'html':
        print('<h3>mutex: %s</h3>' % d)
    else:
        print(d)

    if output_type == 'html':
        print('<table><tr><th>what</th><th>value</th></tr>')
        print('<tr><td># locks/unlocks:</td><td>%d</td></tr>' % n)
        print('<tr><td>total time:</td><td>%.1fus</td></tr>' % sum(durations[d][6]))
        print('<tr><td>average:</td><td>%.6fus</td></tr>' % avg)
        print('<tr><td>standard deviation:</td><td>%.6fus</td></tr>' % sd)
        sorted_list = sorted(durations[d][6])
        print('<tr><td>mininum:</td><td>%.2fus</td></tr>' % sorted_list[0])
        print('<tr><td>median:</td><td>%.2fus</td></tr>' % sorted_list[len(sorted_list) // 2])
        print('<tr><td>maximum:</td><td>%.2fus</td></tr>' % sorted_list[-1])
        print('<tr><td>first unlock seen:</td><td>%s (index %s)</td></tr>' % (my_ctime(int(durations[d][4][1])), durations[d][4][0]))
        print('<tr><td>last unlock seen:</td><td>%s (index %s)</td></tr>' % (my_ctime(int(durations[d][5][1])), durations[d][5][0]))
        print('</table>')

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

        print('<p><br></p>')

        print('<table><tr><th>range</th><th>count</th></tr>')
        for s in slots:
            print('<tr><td>%.2f ... %.2f</td><td>%d</td></tr>' % (s[0], s[0] + steps, s[1]))
        print('</table>')

    else:
        print('\tn: %d, avg: %.6fus, sd: %.6fus</p>' % (n, avg, sd))
        print('')

if output_type != 'html':
    print('')
    print('')

if output_type == 'html':
    print('<p><br><br></p><hr><font size=-1>This <b>locktracer</b> is (C) 2021 by Folkert van Heusden &lt;mail@vanheusden.com&gt;</font></body></ht,l>')

else:
    print('This locktracer is (C) 2021 by Folkert van Heusden <mail@vanheusden.com>')
