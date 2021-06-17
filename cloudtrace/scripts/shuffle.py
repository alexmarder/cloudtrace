import os
import subprocess
import tempfile
from argparse import ArgumentParser
from shutil import copyfile

def shuf(input: str, output: str=None, inplace: bool=False, gzip: bool=False, bzip2: bool=False):
    f = None
    fname = None

    try:
        if input.endswith('.gz'):
            infile = 'zcat'
        elif input.endswith('.bz2'):
            infile = 'bzcat'
        else:
            infile = 'cat'
        infile += ' {}'.format(input)

        if inplace:
            f, fname = tempfile.mkstemp()
            outfile = fname
        else:
            outfile = output

        if gzip or outfile.endswith('.gz') or (inplace and input.endswith('.gz')):
            out = '| gzip >'
        elif bzip2 or outfile.endswith('.bz2') or (inplace and input.endswith('.bz2')):
            out = '| bzip2 >'
        else:
            out = '>'
        out = '{} {}'.format(out, outfile)

        cmd = '{} | shuf {}'.format(infile, out)
        subprocess.run(cmd, shell=True)
        if inplace:
            copyfile(fname, input)
    finally:
        if f is not None and fname is not None:
            os.unlink(fname)

def main():
    parser = ArgumentParser()
    parser.add_argument('-i', '--input')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-I', '--inplace', action='store_true')
    group.add_argument('-o', '--output')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-z', '--gzip', action='store_true')
    group.add_argument('-b', '--bzip2', action='store_true')
    args = parser.parse_args()

    shuf(args.input, output=args.output, inplace=args.inplace, gzip=args.gzip, bzip2=args.bzip2)


if __name__ == '__main__':
    main()
