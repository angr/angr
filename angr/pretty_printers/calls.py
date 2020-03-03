def pretty_print_calls(calls=[]):
    depth=0
    for call in calls:
        if call[1] is True:
            depth=depth+1
        else:
            depth=0
        for i in range(0,depth):
            print("\t", end=''),
        print("[+] %s (" % call[0], end='')
        for i, arg in enumerate(call[2:]):
            if i:
                print(", ",end='')
            print(arg,end='')

        print(")")
        if depth > 0:
            depth=depth-1
