import argparse
import sys
import json
import glob
import binascii
from datetime import datetime, timezone

VERBOSE = False


def parse_args():
    global VERBOSE
    parser = argparse.ArgumentParser(description='Convert an auditd file or line into JSON')
    parser.add_argument('-f', '--file',
                        help='Specify the complete path of file to convert to JSON',
                        default='/var/log/audit/')
    parser.add_argument('-l', '--line',
                        help='Specify a single line in "" to convert to JSON',
                        required=False)
    parser.add_argument('-o', '--output_file',
                        help='Specify a destination file for file conversion  output',
                        default='/var/log/audit/audit.json')
    parser.add_argument('-ol', '--operator-log',
                        help='Specify the type of log to process',
                        default=['execve', 'execveat'],
                        nargs='*')
    parser.add_argument('-v', '--verbose',
                        help='Enable verbose output',
                        action='store_true')
    args = parser.parse_args()
    VERBOSE = args.verbose
    return args, parser


def verbose_print(message):
    if VERBOSE:
        print(message)


def get_time(line):
    timestamp = line.replace('msg=audit(', '').replace('):', '').split(':')
    return datetime.fromtimestamp(float(timestamp[0]), timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


def hex_to_ascii(hex_string):
    if len(hex_string) % 2 != 0:
        hex_string = hex_string + '0'
    bytes_string = binascii.unhexlify(hex_string)
    return bytes_string.decode('utf-8', 'ignore')


def is_hex(s):
    hex_digits = set("0123456789abcdefABCDEF")
    return all(char in hex_digits for char in s)


def make_readable(key):
    return {
        'acct': 'account',
        'res': 'result',
        'comm': 'command-line',
        'pid': 'process_id',
        'uid': 'user_id',
        'auid': 'audit_user_id',
        'exe': 'executable'
    }.get(key, key)


def process_file(path, output, operator_logs):
    with open(path, 'r') as f:
        entries = []
        for line in f:
            if any(operator_log.upper() in line for operator_log in operator_logs):
                entry = process_line(line.replace('\n', ''))
                exclude_noisy_events(entries, entry)

    if output:
        with open(output, 'w') as w:
            json.dump(entries, w, indent=4)


def exclude_noisy_events(entries, entry):
    # Exclude specific events from Kali
    if not ((entry.get('a0') == '/bin/sh' and entry.get('a1') == '/usr/share/kali-themes/xfce4-panel-genmon-vpnip.sh') or
            (entry.get('a0') == 'ip' and entry.get('a1') == 'tuntap') or
            (entry.get('a0') == 'cut' and entry.get('a1') == '-d' and entry.get('a2') == ':' and entry.get('a3') == '-f1') or
            (entry.get('a0') == 'head' and entry.get('a1') == '-n' and entry.get('a2') == '1') or
            (entry.get('a0') == 'ip' and entry.get('a1') == 'a' and entry.get('a2') == 's' and entry.get('a3') == '') or
            (entry.get('a0') == 'grep' and entry.get('a1') == '-o' and entry.get('a2') == '-P' and entry.get('a3') ==  ['(?<=inet )[0-9]{1,3}(\\.[0-9]{1,3}){3}'])):
        entries.append(entry)

# def process_file_and_exclude_noisy_events(file_path):
#     entries = []
#     with open(file_path, 'r') as f:
#         for line in f:
#             entry = process_line(line.replace('\n', ''))
#             exclude_noisy_events(entries, entry)
#     return entries

def process_line(line):
    verbose_print(f"[+] Processing line: {line}")
    entry = {}
    attributes = line.split(' ')
    for attribute in attributes:
        if 'msg=audit' in attribute:
            entry['timestamp'] = get_time(attribute)
        else:
            attribute = attribute.replace('msg=', '').replace('\'', '').replace('"', '').split('=')
            if len(attribute) == 2:
                key, value = attribute
                if 'cmd' in key or 'proctitle' in key:
                    value = bytearray.fromhex(value).decode()
                if is_hex(value) and len(value) > 10:
                    value = hex_to_ascii(value).strip().split('\n')
                    print(f"value:\n {value}\n\n")
                entry[make_readable(key)] = value
    return entry


def main():
    args, parser = parse_args()

    if args.file:
        verbose_print(f"[+] Converting file(s): {args.file}")
        if args.file.endswith('.log'):
            process_file(args.file, args.output_file, args.operator_log)
        else:
            for log_file in glob.glob(args.file + '*.log*'):
                process_file(log_file, args.output_file, args.operator_log)
        verbose_print("[+] Conversion completed!")
    elif args.line:
        verbose_print("[+] Converting line...")
        print(json.dumps(process_line(args.line), indent=4))
        verbose_print("[+] Conversion completed!")
    else:
        print("[!] No actionable arguments supplied.")
        parser.print_help()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print('terminated.')
        sys.exit(0)
