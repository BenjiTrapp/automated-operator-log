import argparse
import time
import sys
import json
import glob
import binascii

VERBOSE = False

def parse_args():
    global VERBOSE
    parser = argparse.ArgumentParser(description='Convert an auditd file or line into JSON')
    parser.add_argument('-f', '--file', help='Specify the complete path of file to convert to JSON', default='/var/log/audit/')
    parser.add_argument('-l', '--line', help='Specify a single line in "" to convert to JSON', required=False)
    parser.add_argument('-o', '--output_file', help='Specify a destination file for file conversion output', default='/var/log/audit/audit.json')
    parser.add_argument('-ol', '--operator-log', help='Specify the type of log to process', default=['execve', 'execveat'], nargs='*')
    parser.add_argument('-v', '--verbose', help='Enable verbose output', action='store_true')
    args = parser.parse_args()
    VERBOSE = args.verbose
    return args, parser

def verbose_print(message):
    if VERBOSE:
        print(message)

def get_time(line):
    timestamp = line.replace('msg=audit(','').replace('):','').split(':')
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(timestamp[0])))

def hex_to_ascii(hex_string):
    if len(hex_string) % 2 != 0:
        hex_string =  hex_string + '0'
    bytes_string = binascii.unhexlify(hex_string)
    return bytes_string.decode('utf-8', 'ignore')

def is_hex(s):
    hex_digits = set("0123456789abcdefABCDEF")
    return all(char in hex_digits for char in s)

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
    with open(path,'r') as f:
        entries = [process_line(line.replace('\n','')) for line in f if any(operator_log.upper() in line for operator_log in operator_logs)]

    if output:
        with open(output, 'w') as w:
            json.dump(entries, w, indent=4)

def process_line(line):
    verbose_print(f"[+] Processing line: {line}")
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
                if is_hex(value) and len(value) > 10:
                    value = hex_to_ascii(value)
                entry[make_readable(key)] = value
    return entry

def main():
    args, parser = parse_args()

    if args.file:
        verbose_print(f"[+] Converting file(s): {args.file}")
        if args.file.endswith('.log'):
            process_file(args.file, args.output_file, args.operator_log)
        else:
            for log_file in glob.glob(args.file + '*.log'):
                process_file(log_file, args.output_file, args.operator_log)
        verbose_print("[+] Conversion completed!")
    elif args.line:
        verbose_print("[+] Converting line...")
        print(json.dumps(process_line(args.line), indent=4))
        verbose_print(args, "[+] Conversion completed!")
    else:
        print("[!] No actionable arguments supplied.")
        parser.print_help()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print('terminated.')
        sys.exit(0)