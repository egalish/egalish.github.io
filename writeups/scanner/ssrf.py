#!/usr/bin/env python3

import sys
import argparse

from scanner import Scanner, print_colored

def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    scan_parser = subparsers.add_parser(name="scan")
    get_parser = subparsers.add_parser(name="get")

    scan_parser.add_argument("-t", "--targets", required=True)
    scan_parser.add_argument("-s", "--server-url", required=True)
    scan_parser.add_argument("-l", "--logfile", default="scan.log")
    scan_parser.add_argument("-v", "--verbose", action="store_true")
    
    get_parser.add_argument("-s", "--server-url", required=True)
    get_parser.add_argument("-u", "--url", required=True)
    get_parser.add_argument("-o", "--output-file", default=None)
    get_parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()
    
    match sys.argv[1]:

        case "scan":
            with open(args.targets, "r") as f:
                targets = f.read()[:-1].split("\n")
            
            server_url = args.server_url
            logfile = args.logfile
            verbose = args.verbose
            
            try:
                scanner = Scanner(
                    server_url,
                    target_list=targets,
                    logfile=logfile,
                    verbose=verbose
                    )

                scanner.scan()
                scanner.close()
            except KeyboardInterrupt:
                scanner.close()
                exit(1)
            except Exception as e:
                print_colored(f"[!] Encountered Exception in main: {e}")
                exit(1)

        case "get":
            try:
                server_url = args.server_url
                target_url = args.url.replace("\\r", "\r").replace("\\n", "\n")
                filename = args.output_file
                verbose = args.verbose

                scanner = Scanner(
                    server_url,
                    verbose=verbose
                )

                scanner.get(target_url, filename)
                scanner.close()
            except KeyboardInterrupt:
                scanner.close()
                exit(1)
            except Exception as e:
                print_colored(f"[!] Encountered Exception in main: {e}")
                exit(1)

        case _:
            print_colored(f"[*] Unrecognized command {sys.argv[1]}")
            exit(1)




if __name__ == "__main__":
    main()
