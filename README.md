# AES PADDING CRACKER
This tool is the C++ version, with improvements, of my AES-CBC-CRACKER tool also available on my Github repo.

The goal is to exploit a padding oracle to recover a plaintext.

# Usage
First, install a required package and compile the project:
```bash
sudo apt-get install libboost-all-dev
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
./AES-padding-cracker -u "http://challenge01.root-me.org/realiste/ch12/index.aspx" -m GET -d "c=" -b 16 -c 59873749DC0D3A4ACC7F19D711853685EFCDBFECDF85D6B3AF6171F793CC20B4 -e "Padding Error"
```


# TODO:
- multithreading + mutex = DONE
- better error handling, with clean exit
- Arg parsing, fix alloc error
- socket
- POST

