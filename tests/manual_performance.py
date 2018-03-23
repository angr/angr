#!/usr/bin/env python

import angr
import argparse
import sys
import time
import os
import math
import random
import resource
import multiprocessing

from tabulate import tabulate

from os.path import join, dirname, realpath

from progressbar import ProgressBar, Percentage, Bar

test_location = str(join(dirname(realpath(__file__)), '../../binaries/tests'))


class Timer(object):

    def __enter__(self):
        self.start = time.time()
        return self

    def __exit__(self, *args):
        self.end = time.time()
        self.msecs = (self.end - self.start) * 1000

def mean(r):
    return 0. if not r else float(sum(r)) / len(r)

def std(r):
    average = mean(r)
    return math.sqrt(float(sum(pow(x - average, 2) for x in r)) / len(r))


def print_results(tests):
    table_runs = []
    table_mems = []
    for name, test in tests.items():
        runs = test['runs']
        table_runs.append([name, str(min(runs)), str(max(runs)), str(mean(runs)), str(std(runs))])
    for name, test in tests.items():
        mems = test['mems']
        table_mems.append([name, str(min(mems)), str(max(mems)), str(mean(mems)), str(std(mems))])
    header = ['name', 'min', 'max', 'avg', 'std']

    print('Timing (in milliseconds)')
    print(tabulate(table_runs, headers=header))
    print('Maximum RAM usage (in MB)')
    print(tabulate(table_mems, headers=header))


def run_counter(path):
    p = angr.Project(path)

    sm = p.factory.simgr()
    sm.run(n=500)


def run_cfg_analysis(path):
    load_options = {}
    load_options['auto_load_libs'] = False
    p = angr.Project(path,
                     load_options=load_options,
                     translation_cache=True
                     )
    p.analyses.CFGAccurate()


def time_one(args, test, queue):
    filepath = test['filepath']
    func = test['test_func']

    random.seed(args.seed)
    with Timer() as t:
        func(filepath)
    queue.put(t.msecs)
    queue.put(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1000.0)


parser = argparse.ArgumentParser(description='angr performance tests')
parser.add_argument(
    '-n', '--n-runs', default=100, type=int,
    help='How many runs to perform for each test (default: 100)')
parser.add_argument(
    '-s', '--seed', default=1234, type=int,
    help='Seed for random (default: 1234)')

args = parser.parse_args()

tests = {
    'fauxware_cfg_i386': {
        'filepath': join(test_location, 'i386', 'fauxware'),
        'test_func': run_cfg_analysis
    }
}

# Add counter tests
arch_counter = [
    'i386',
    'armel',
    'armhf',
    'i386',
    'mips',
    'mipsel',
    'ppc',
    'ppc64',
    'x86_64',
]

for arch in arch_counter:
    tests['counter_' + arch] = {
        'filepath': join(test_location, arch, 'counter'),
        'test_func': run_counter
    }


print('Seed: ' + str(args.seed))
print('N runs: ' + str(args.n_runs))
queue = multiprocessing.Queue()
for test in tests:
    runs = []
    mems = []
    widgets = ['',
               Percentage(), ' ',
               Bar()
               ]
    print(test)
    pbar = ProgressBar(maxval=args.n_runs, widgets=widgets).start()
    for i in range(0, args.n_runs):
        p = multiprocessing.Process(target=time_one, args=(args, tests[test], queue))
        p.start()
        p.join()
        runs.append(queue.get())
        mems.append(queue.get())
        pbar.update(i + 1)
    print('')
    tests[test]['runs'] = runs
    tests[test]['mems'] = mems

print_results(tests)
