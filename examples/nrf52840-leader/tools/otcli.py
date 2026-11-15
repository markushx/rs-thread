# Drive an OpenThread CLI on a serial port (115200 8N1) without pyserial.
# Usage:  python3 -I tools/otcli.py <port> <cmd> [<cmd>...]
# Each command is sent as a line; the output up to the "Done"/"Error" line is
# printed. A command of the form `sleep:<s>` waits, `drain:<s>` prints the output that arrives meanwhile. The shared test dataset
# hex string is DATASET_HEX in src/lib.rs.
import os, sys, termios, time, select


def open_port(path):
    fd = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    a = termios.tcgetattr(fd)
    a[0] = 0
    a[1] = 0
    a[3] = 0
    a[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
    a[4] = a[5] = termios.B115200
    a[6][termios.VMIN] = 0
    a[6][termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSANOW, a)
    return fd


def read_until_done(fd, timeout, marker='Done'):
    buf = b''
    end = time.time() + timeout
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            buf += os.read(fd, 4096)
            lines = buf.decode(errors='replace').splitlines()
            if any(l.strip() == marker or l.startswith('Error') for l in lines):
                break
    return buf.decode(errors='replace')


def run(port, cmds, timeout=10):
    fd = open_port(port)
    try:
        os.write(fd, b'\n')
        time.sleep(0.3)
        try:
            os.read(fd, 4096)
        except BlockingIOError:
            pass
        for c in cmds:
            if c.startswith('sleep:'):
                time.sleep(float(c[6:]))
                continue
            if c.startswith('drain:'):
                # Print asynchronous output (UDP receive, scan results, ...).
                end = time.time() + float(c[6:])
                while time.time() < end:
                    r, _, _ = select.select([fd], [], [], 0.2)
                    if r:
                        print(os.read(fd, 4096).decode(errors='replace').rstrip())
                continue
            os.write(fd, c.encode() + b'\n')
            # `ping` prints its summary line first, then Done.
            marker = 'Done'
            t = timeout
            if c.startswith('ping'):
                n = int(c.split()[3]) if len(c.split()) > 3 else 1
                t = timeout + n * 1.5
            print(read_until_done(fd, t, marker).rstrip())
            if c.startswith('ping'):
                time.sleep(0.2)
    finally:
        os.close(fd)


if __name__ == '__main__':
    run(sys.argv[1], sys.argv[2:])
