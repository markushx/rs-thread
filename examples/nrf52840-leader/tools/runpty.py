import os, pty, subprocess, sys, time, select, signal
log, secs = sys.argv[1], int(sys.argv[2])
cmd = sys.argv[3:]
m, s = pty.openpty()
p = subprocess.Popen(cmd, stdin=s, stdout=s, stderr=s, close_fds=True, start_new_session=True)
os.close(s)
end = time.time() + secs
with open(log, 'wb') as f:
    while time.time() < end:
        r, _, _ = select.select([m], [], [], 1)
        if r:
            try:
                d = os.read(m, 65536)
            except OSError:
                break
            if not d:
                break
            f.write(d); f.flush()
        if p.poll() is not None and not r:
            break
try:
    os.killpg(p.pid, signal.SIGINT)
    time.sleep(2)
    os.killpg(p.pid, signal.SIGKILL)
except Exception:
    pass
