# AES PADDING CRACKER
This tool is the C++ version, with improvements, of my AES-CBC-CRACKER tool also available on my Github repo.

The goal is to exploit a padding oracle to recover a plaintext.

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
  -d, --data arg           Data to send (default: "")
  -c, --cypher arg         Cypher text
  -b, --block-size arg     Block size (8,16,32,64)
  -e, --padding-error arg  Padding error text
  -h, --help               Print usage
```

Example:
```bash
./AES-padding-cracker -u "http://example.com/index.php" -m GET -d "c=" -b 16 -c 59873749DC0D3A4ACC7F19D711853685EFCDBFECDF85D6B3AF6171F793CC20B4 -e "Padding Error"
```


# TODO:
- multithreading + mutex = DONE
- Arg parsing, fix alloc error = DONE
- better error handling, with clean exit
- socket
- POST

