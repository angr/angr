import angr
import simuvex


def num_paths(pg):
    index = 0
    for stash in pg.stashes:
        index += len(pg.stashes[stash])
    return index

def test_bin_ls():
    p = angr.Project('/bin/cat', load_options={'auto_load_libs': False})

    argv = ['/bin/cat', "/etc/passwd"]

    s = p.factory.full_init_state(args=argv,
                                  remove_options={simuvex.options.LAZY_SOLVES},
                                  concrete_fs=True)

    pg = p.factory.path_group(s)
    pg.use_technique(angr.exploration_techniques.AFL())

    num_steps = 0
    while num_paths(pg) < 1000:
        print "Doing another step, only at {} paths, {} active".format(num_paths(pg), len(pg.active))
        pg.run(n=1)
        num_steps += 1

    print "Finished, {} total paths after {} steps".format(num_paths(pg), num_steps)

    covered_addresses = {}
    for stash in pg.stashes:
        for path in pg.stashes[stash]:
            for addr in path.addr_trace:
                if addr not in covered_addresses:
                    covered_addresses[addr] = 0
                covered_addresses[addr] += 1

    print "Total number of distinct covered addresses: {}".format(len(covered_addresses.keys()))

    for stash in pg.stashes:
        s = sorted(pg.stashes[stash], key=lambda x: x.length)
        print "{}: {}".format(stash, s)




if __name__ == '__main__':
    # import sys
    # globals()['test_' + sys.argv[1]]()
    test_bin_ls()

