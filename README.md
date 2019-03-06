# sslease
## Asynchronously invoke testssl on a variety of targets and output to CSV
Requires testssl and python 3.7

### Args
```
usage: Aggregate TestSSL output [-h] -t TARGET [-o OUT_DIR]
                                [-p THREAD_POOL_SIZE]

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Target(s) to test SSL/TLS configuration of
  -o OUT_DIR, --out-dir OUT_DIR
                        Directory to write files to
  -p THREAD_POOL_SIZE, --thread-pool-size THREAD_POOL_SIZE
                        Set the maximum number of concurrent scans
```

### Info
Targets can be specified in a variety of formats and supplied as either a single argument
or a file of newline separated targets.

Valid input includes:
```
https://github.com/
https://github.com:443
https://github.com:65535
github.com:65535
https://127.0.0.1:443
127.0.0.0/23
```
Output is written in to the current directory under the `sslease_reports` folder by default.
CSVs are named after the vulnerability as output by testssl and as such vary in quality.
CSVs contain the IP address(es) of the specified target(s), along with their port(s) if specified.

### Usage Examples
#### Single target
```
python sslease.py -t 127.0.0.1:443
```
### Target file, custom thread pool size and custom output directory
```
python sslease.py -t scope.file --thread-pool-size 15 --out-dir ~/projects/out/
```

### Installing in pipenv
```
pipenv install
pipenv shell
```

### Running Tests
```
pipenv shell
tox
```
