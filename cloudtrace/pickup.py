import getpass
import socket
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from glob import glob

username = getpass.getuser()

def pickup(filename, host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.send('{}:{}\n'.format(username, filename).encode())
        s.close()
    except:
        print('Unable to connect to {}:{}.'.format(host, port))
        pass


def main():
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument('-p', '--pattern', required=True, help='Glob style regex or filename.')
    parser.add_argument('-r', '--remote', required=True, help='Remote machine name or IP address.')
    args = parser.parse_args()

    host, _, port = args.remote.partition(':')
    port = int(port)
    pattern = args.pattern
    files = glob(pattern)
    for f in files:
        pickup(f, host, port)
