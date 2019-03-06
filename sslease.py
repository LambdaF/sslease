#!/usr/bin/python3.7
import argparse
import json
import tempfile
import os
import urllib.parse
import asyncio
import socket
import ipaddress
from itertools import chain


def stripURI(target: str) -> str:
    """
    Strip a given URI to just its hostname or IP
    Intended to be used for simplying filenames
    Ports are appended with -<portnum>
    e.g. https://github.com:443 -> github.com-443
    """
    result = urllib.parse.urlparse(target)
    if result.hostname:
        if result.port:
            return f"{result.hostname}-{result.port}"
        return result.hostname

    # Manually strip ports of no schema was in given target
    return target.replace(':', '-')


def hostnameToIP(target: str) -> str:
    """ Attempts to reduce a given URL to an IP address """
    try:
        result = socket.gethostbyname(target)
    except socket.error:
        return target
    return result


def formatCommand(tempDir, target, args="--warnings batch --quiet"):
    """
    Formats given arguments in to testssl command line format
    """
    return f"testssl -oj {tempDir}/{stripURI(target)}.ssl {args} {target}"


def expandRange(cidr: str) -> list:
    """ Attempts to expand given CIDR range """
    if cidr[0].isalpha() or cidr.find(':') > -1:
        return [cidr]
    return [str(ip) for ip in ipaddress.IPv4Network(cidr)]


def parseTargets(fileName: str) -> set:
    """
    Parses a file of new line seperated IP addresses/CIDR ranges/URLs
    Returns a set of results
    """
    targets = set()
    with open(fileName, 'r') as f:
        targets = [expandRange(hostnameToIP(x.strip()))
                   for x in f.read().split()]
        targets = chain.from_iterable(targets)

    return set(targets)


async def runCommand(cmd):
    """
    Run a given command asynchronously and return the output
    """
    print(f"[+] Running {cmd}")

    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    result, _ = await proc.communicate()

    print(f"[!] Completed {cmd}")

    return result


def writeResults(tempDir, outDir):
    """
    Parse json stored in temporary folder and write results
    to given outDir in CSVs of vuln titles
    """
    csv = {}
    for root, _, files in os.walk(tempDir):
        for file in files:
            parsed = ''
            with open("{}/{}".format(root, file)) as f:
                parsed = json.loads(f.read())
                vulns = [x for x in parsed if (
                    x['severity'] != "OK") and (x['severity'] != "INFO")]
                for item in vulns:
                    id = "".join([c if c.isalnum() or c ==
                                  "_" else '' for c in item['id']])
                    ip = stripURI(file).replace("-", ":")[:-4]
                    if id in csv:
                        csv[id] += f",{ip}"
                    else:
                        csv[id] = f"{ip}"

    print("[+] Writing output to {}".format(outDir))
    if not os.path.exists(outDir):
        os.mkdir(outDir)
    for k in csv:
        with open("{}/{}.csv".format(outDir, k), 'w') as f:
            f.write(k + '\n')
            f.write(csv[k])


async def main(target, outDir, maxConcurrent):
    """
    Asynchronously run testssl, then invoke result writing to CSV
    Opens a temporary directory using tempfile
    """
    ips = set()
    if os.path.isfile(target):
        print(f"[-] Parsing scope file '{target}'")
        ips = list(parseTargets(target))
    else:
        ips = expandRange(hostnameToIP(target))

    with tempfile.TemporaryDirectory() as tempDir:
        print("[-] Working in {}".format(tempDir))

        tasks = set()
        for ip in ips:
            if len(tasks) >= maxConcurrent:
                _, tasks = await asyncio.wait(
                    tasks,
                    return_when=asyncio.FIRST_COMPLETED
                )
            tasks.add(asyncio.create_task(
                runCommand(formatCommand(tempDir, ip))))

        await asyncio.wait(tasks)

        writeResults(tempDir, outDir)


if __name__ == "__main__":
    parser = argparse.ArgumentParser("Aggregate TestSSL output")
    parser.add_argument("-t", "--target", default="",
                        help="Target(s) to test SSL/TLS configuration of",
                        required=True)
    parser.add_argument("-o", "--out-dir", default="sslease_reports",
                        help="Directory to write files to")
    parser.add_argument("-p", "--thread-pool-size", type=int, default=10,
                        help="Set the maximum number of concurrent scans")
    args = parser.parse_args()

    print("[+] Running TestSSL scans, be patient...")
    asyncio.run(main(args.target, args.out_dir, args.thread_pool_size))
