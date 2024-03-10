import argparse
import time
import sys
import json
import glob

def parse_args():
    parser = argparse.ArgumentParser(description='Convert an auditd file or line into JSON')
    parser.add_argument('-f', '--file', help='Specify the complete path of file to convert to JSON', default='/var/log/audit/')
    parser.add_argument('-l', '--line', help='Specify a single line in "" to convert to JSON', required=False)
    parser.add_argument('-o', '--output_file', help='Specify a destination file for file conversion output', required=False)
    parser.add_argument('-ol', '--operator-log', help='Specify the type of log to process', default=['execve', 'execveat'], nargs='*')
    return parser.parse_args(), parser

def get_time(line):
    timestamp = line.replace('msg=audit(','').replace('):','').split(':')
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(timestamp[0])))

def make_readable(key):
    return{
        'acct': 'account',
        'res': 'result',
        'comm': 'command-line',
        'pid': 'process_id',
        'uid': 'user_id',
        'auid': 'audit_user_id',
        'exe': 'executable'
    }.get(key, key)

def process_file(path, output, operator_logs):
    entries = []
    with open(path,'r') as f:
        for line in f:
            for operator_log in operator_logs:
                if operator_log in line:
                    entry = process_line(line.replace('\n',''))
                    entries.append(entry)
                    break  # Stop checking other operator_logs once a match is found

    if output:
        with open(output, 'w') as w:
            json.dump(entries, w, indent=4)

def process_line(line):
    entry = {}
    attributes = line.split(' ')
    for attribute in attributes:
        if 'msg=audit' in attribute:
            entry['timestamp'] = get_time(attribute)
        else:
            attribute = attribute.replace('msg=','').replace('\'','').replace('"','').split('=')
            if len(attribute) == 2:
                key, value = attribute
                if 'cmd' in key or 'proctitle' in key:
                    value = bytearray.fromhex(value).decode()
                entry[make_readable(key)] = value
    return entry

def main():
    args, parser = parse_args()

    if args.file:
        print("Converting file(s)...")
        if args.file.endswith('.log'):
            process_file(args.file, args.output_file, args.operator_log)
        else:
            # If a directory is provided, process all .log files in it
            for log_file in glob.glob(args.file + '*.log'):
                process_file(log_file, args.output_file, args.operator_log)
        print("Conversion completed!")
    elif args.line:
        print("Converting line...")
        print(json.dumps(process_line(args.line), indent=4))
        print("Conversion completed!")
    else:
        print("No actionable arguments supplied.")
        parser.print_help()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print('terminated.')
        sys.exit(0)