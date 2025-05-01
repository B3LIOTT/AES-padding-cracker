# AES PADDING CRACKER
The fastest pading oracle cracker, in C++ with multithreading (1 thread per block).

The goal was to make a C++ version, with improvements, of my AES-CBC-CRACKER tool also available on my Github repo.

The goal is to exploit a padding oracle to recover a plaintext.

Thanks to [cxxopts](https://github.com/jarro2783/cxxopts) I saved a lot of time on parsing arguments.

# Usage
First, compile the project:
```bash
make
```

And then, use this wonderful tool:
```bash
Usage:
  oracle_padding_attack [OPTION...]

  -u, --url arg            Url pointing to the oracle
  -m, --method arg         SOCKET, GET or POST method
  -p, --port arg           Port number for SOCKET method (default: 0)
  -d, --data arg           Data to send (default: "")
  -c, --cypher arg         Cypher text
  -b, --block-size arg     Block size (8,16,32,64)
  -e, --padding-error arg  Padding error text
  -h, --help               Print usage
```

Example for GET requests:
```bash
./AES-padding-cracker -u "http://example.com/index.php" -m GET -d "c=" -b 16 -c 59873749DC0D3A4ACC7F19D711853685EFCDBFECDF85D6B3AF6171F793CC20B4 -e "Padding Error"
```

Example for POST requests:
TODO

Example for socket connections:
```bash
./AES-padding-cracker AES-padding-cracker -u "example.com" -p 12345 -m "SOCKET" -b 16 -c "BC16542433100D9522DC3B6428D4FF5F7FC67B4994323C47ED09F185C3CE7A2E" -e "Padding Error"
```




# TODO:
- better error handling, with clean exit
- POST method

