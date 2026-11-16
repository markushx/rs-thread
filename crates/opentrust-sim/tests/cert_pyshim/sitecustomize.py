"""Lets thread-cert's packet verification run on macOS.

`thread_cert.py` raises NotImplementedError in `tearDown` unless
`os.uname().sysname == "Linux"`. With `OPENTRUST_FAKE_LINUX_UNAME=1` the
harness puts this directory on `PYTHONPATH` and `os.uname()` reports Linux.
"""
import os

if os.environ.get("OPENTRUST_FAKE_LINUX_UNAME") == "1":
    _real_uname = os.uname

    def _uname():
        r = _real_uname()
        return os.uname_result(("Linux",) + tuple(r)[1:])

    os.uname = _uname

    # pyshark (`FileCapture`) calls `asyncio.get_event_loop_policy().get_event_loop()`
    # in the main thread, which raises on Python 3.14 without a current loop.
    import asyncio
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        asyncio.set_event_loop(asyncio.new_event_loop())

    # pyshark also installs a `SafeChildWatcher`, which Python 3.14 removed
    # (subprocesses are watched without it).
    class _NoWatcher:
        def attach_loop(self, loop):
            pass

    if not hasattr(asyncio, "set_child_watcher"):
        asyncio.SafeChildWatcher = _NoWatcher
        asyncio.set_child_watcher = lambda watcher: None
        asyncio.get_child_watcher = lambda: _NoWatcher()

    # tshark 4.6 prints booleans as "True" / "False"; the field parsers of
    # `pktverify` expect "1" / "0". Wrap the automatic parser once the module
    # is imported.
    import importlib.abc
    import sys

    class _PatchLayerFields(importlib.abc.MetaPathFinder):
        def find_spec(self, name, path, target=None):
            if name != "pktverify.layer_fields":
                return None
            sys.meta_path.remove(self)
            spec = importlib.util.find_spec(name)
            orig_exec = spec.loader.exec_module

            def exec_module(module):
                orig_exec(module)
                auto = module._auto

                def parse(v):
                    dv = v.get_default_value()
                    if dv in ("True", "False"):
                        return 1 if dv == "True" else 0
                    return auto(v)

                for k, f in list(module._LAYER_FIELDS.items()):
                    if f is auto:
                        module._LAYER_FIELDS[k] = parse

            spec.loader.exec_module = exec_module
            return spec

    import importlib.util

    sys.meta_path.insert(0, _PatchLayerFields())
