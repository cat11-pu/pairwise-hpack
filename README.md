# hpack

An HPACK (RFC 7541) header compression kernel written with the Python standard
library only. It opens no socket and touches no file: a header block goes into
a `Decoder` and comes back as a header list, a header list goes into an
`Encoder` and comes back as the block that carries it. Both sides keep a
dynamic table of their own, with the static table, the Huffman code of
Appendix B, the integer and string primitives and the eviction rules of the
format.

## Layout

- hpack/core.py: static table, Huffman code, dynamic table, decoder, encoder
- tests/test_core.py: behaviour tests

## Running the tests

Run them from the project root:

    python3 -m unittest discover -s tests -v
