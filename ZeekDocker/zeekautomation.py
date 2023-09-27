from datetime import datetime
import pandas as pd
import subprocess
import argparse
from pathlib import Path

def read_zeek_header(path):
    header = {}
    f = open(path, 'r')
    line = f.readline()
    if '#separator' not in line:
        raise ValueError('Not a valid Zeek log file')
    header['separator'] = line.rstrip().split()[-1].encode().decode('unicode_escape')
    line = f.readline()
    header['set_separator'] = line.rstrip().split()[-1]
    line = f.readline()
    header['empty_field'] = line.rstrip().split()[-1]
    line = f.readline()
    header['unset_field'] = line.rstrip().split()[-1]
    line = f.readline()
    header['path'] = line.rstrip().split()[-1]
    line = f.readline()
    header['open'] = datetime.strptime(str(line.rstrip().split()[-1]),"%Y-%m-%d-%H-%M-%S")
    line = f.readline()
    header['fields'] = line.rstrip().split()[1:]
    line = f.readline()
    header['types'] = line.rstrip().split()[1:]
    return header


def read_zeek(path, **kwargs):
    header = read_zeek_header(path)
    df = pd.read_csv(path, skiprows=8, names=header['fields'], sep=header['separator'], comment='#', **kwargs)
    return df

def run_zeek(pcap_file: Path, output_dir: Path):
    cmd = ['zeek', '-C', '-r', pcap_file.as_posix(), 'local']
    subprocess.run(cmd, cwd=output_dir.as_posix())

def run(pcap_dir: Path, output_dir: Path, logs: list[str]):
    # create zeek dir in /tmp
    zeek_dir = Path('/tmp/zeek')
    zeek_dir.mkdir(parents=True, exist_ok=True)
    for pcap in pcap_dir.iterdir():
        if pcap.suffix == '.pcap':
            run_zeek(pcap, output_dir=zeek_dir)
            for log in logs:
                log_name = Path(log).stem
                zeek_log = zeek_dir/log
                if zeek_log.exists():
                    df = read_zeek(zeek_log)
                    df.to_csv(output_dir/(log_name + '_' + pcap.stem + '.csv'))
                else:
                    print(f'did not found {zeek_log}')
def main():
    arg_parser = argparse.ArgumentParser(description='Zeek automation')
    arg_parser.add_argument('-i', '--input', help='Path to a directory with pcap files', required=True)
    arg_parser.add_argument('-o', '--output', help='Path to the output folder', required=True)
    arg_parser.add_argument('-l', '--logs', help='List of log files to save as Csv', required=True, nargs='+')
    args = arg_parser.parse_args()

    run(Path(args.input), Path(args.output), args.logs)


if __name__ == '__main__':
    main()