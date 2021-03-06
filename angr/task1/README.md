# Solution

```python
    p = angr.Project("./fauxware", auto_load_libs=False)
    state = p.factory.entry_state()
    simgr = p.factory.simgr(state)

    simgr.run()

    simgr.move(from_stash="deadended", to_stash="succ_auth", filter_func=lambda s: b'Welcome' in s.posix.dumps(1))

    print(simgr.succ_auth[0].posix.dumps(0)) # b'\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00'
```