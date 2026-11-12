# Drive an OpenThread CLI on a serial port (115200 8N1) without pyserial.
# Usage:  python3 -I tools/otcli.py <port> <cmd> [<cmd>...]
# Each command is sent as a line; the output up to the "Done"/"Error" line is
# printed. A command of the form `sleep:<s>` waits. The shared test dataset
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


def read_until_done(fd, timeout):
    buf = b''
    end = time.time() + timeout
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            buf += os.read(fd, 4096)
            lines = buf.decode(errors='replace').splitlines()
            if any(l.strip() == 'Done' or l.startswith('Error') for l in lines):
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
            os.write(fd, c.encode() + b'\n')
            print(read_until_done(fd, timeout).rstrip())
    finally:
        os.close(fd)


if __name__ == '__main__':
    run(sys.argv[1], sys.argv[2:])
