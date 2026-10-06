"""Behaviour tests for the HPACK kernel.

Run them from the project root:

    python3 -m unittest discover -s tests -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hpack.core import (
    Decoder,
    Encoder,
    HPACKError,
    encode_integer,
    encode_string,
    huffman_decode,
    huffman_encode,
    huffman_length,
)


def incremental(name, value):
    """A literal field that asks to join the dynamic table."""
    return b"\x40" + encode_string(name) + encode_string(value)


class IndexedFieldTest(unittest.TestCase):
    def test_indices_run_static_first_then_newest_dynamic(self):
        decoder = Decoder()
        block = (
            encode_integer(2, 7, 0x80)
            + encode_integer(4, 7, 0x80)
            + incremental("x-a", "1")
            + incremental("x-b", "2")
            + encode_integer(62, 7, 0x80)
            + encode_integer(63, 7, 0x80)
        )
        self.assertEqual(
            decoder.decode(block),
            [(":method", "GET"), (":path", "/"), ("x-a", "1"), ("x-b", "2"),
             ("x-b", "2"), ("x-a", "1")],
        )
        self.assertEqual(decoder.table.entries, [("x-a", "1"), ("x-b", "2")])


class LiteralFormTest(unittest.TestCase):
    def test_a_literal_without_indexing_leaves_the_table_alone(self):
        decoder = Decoder()
        block = b"\x01" + encode_string("example.com")
        self.assertEqual(decoder.decode(block), [(":authority", "example.com")])
        self.assertEqual(decoder.table.entries, [])
        self.assertEqual(decoder.table.size, 0)

    def test_the_two_plain_literal_forms_keep_their_names(self):
        decoder = Decoder()
        block = (
            b"\x11" + encode_string("example.com")
            + b"\x01" + encode_string("example.com")
        )
        self.assertEqual(
            decoder.decode(block),
            [(":authority", "example.com"), (":authority", "example.com")],
        )
        self.assertEqual(decoder.table.entries, [])
        encoder = Encoder()
        self.assertEqual(
            decoder.decode(encoder.encode([("authorization", "Bearer z")])),
            [("authorization", "Bearer z")],
        )
        self.assertEqual(decoder.table.entries, [])


class DynamicTableTest(unittest.TestCase):
    def test_a_full_table_keeps_the_entries_that_fit(self):
        # x-a:1 and x-b:2 take 36 octets each.
        decoder = Decoder(max_size=72)
        decoder.decode(incremental("x-a", "1") + incremental("x-b", "2"))
        self.assertEqual(decoder.table.entries, [("x-a", "1"), ("x-b", "2")])
        self.assertEqual(decoder.table.size, 72)
        decoder.decode(incremental("x-c", "3"))
        self.assertEqual(decoder.table.entries, [("x-b", "2"), ("x-c", "3")])
        self.assertEqual(decoder.table.size, 72)

    def test_a_size_update_evicts_down_to_the_new_limit(self):
        decoder = Decoder()
        decoder.decode(
            incremental("x-a", "1")
            + incremental("x-b", "2")
            + incremental("x-c", "3")
        )
        self.assertEqual(
            decoder.table.entries, [("x-a", "1"), ("x-b", "2"), ("x-c", "3")]
        )
        self.assertEqual(decoder.decode(encode_integer(36, 5, 0x20)), [])
        self.assertEqual(decoder.table.max_size, 36)
        self.assertEqual(decoder.table.size, 36)
        self.assertEqual(decoder.table.entries, [("x-c", "3")])
        self.assertEqual(decoder.decode(encode_integer(62, 7, 0x80)), [("x-c", "3")])

    def test_a_size_update_above_the_limit_is_refused(self):
        decoder = Decoder(max_size=64)
        with self.assertRaises(HPACKError):
            decoder.decode(encode_integer(256, 5, 0x20))
        self.assertEqual(decoder.table.max_size, 64)


class EncoderTest(unittest.TestCase):
    def test_a_repeated_field_does_not_join_the_table_twice(self):
        encoder = Encoder()
        block = encoder.encode([("x-a", "1"), ("x-b", "2"), ("x-a", "1")])
        self.assertEqual(
            block,
            incremental("x-a", "1")
            + incremental("x-b", "2")
            + encode_integer(63, 7, 0x80),
        )
        self.assertEqual(encoder.table.entries, [("x-a", "1"), ("x-b", "2")])
        self.assertEqual(encoder.table.size, 72)
        decoder = Decoder()
        self.assertEqual(
            decoder.decode(block), [("x-a", "1"), ("x-b", "2"), ("x-a", "1")]
        )
        self.assertEqual(decoder.table.entries, [("x-a", "1"), ("x-b", "2")])


class HuffmanTest(unittest.TestCase):
    def test_the_huffman_form_is_used_and_reported_correctly(self):
        for text in ("302", "abc123", "www.example.com", "gzip, deflate"):
            with self.subTest(text=text):
                self.assertEqual(huffman_length(text), len(huffman_encode(text)))
        self.assertEqual(encode_string("302"), b"\x82\x64\x02")
        self.assertEqual(
            encode_string("www.example.com"),
            b"\x8c" + bytes.fromhex("f1e3c2e5f23a6ba0ab90f4ff"),
        )

    def test_huffman_strings_come_back_unchanged(self):
        for text in ("www.example.com", "custom-key", "no-cache",
                     "Mon, 21 Oct 2013 20:13:21 GMT"):
            with self.subTest(text=text):
                self.assertEqual(huffman_decode(huffman_encode(text)), text)
        self.assertEqual(
            huffman_encode("www.example.com"),
            bytes.fromhex("f1e3c2e5f23a6ba0ab90f4ff"),
        )
        with self.assertRaises(HPACKError):
            huffman_decode(b"\xff")


class ErrorTest(unittest.TestCase):
    def test_a_table_index_out_of_range_is_an_error(self):
        decoder = Decoder()
        with self.assertRaises(HPACKError):
            decoder.decode(encode_integer(62, 7, 0x80))
        with self.assertRaises(HPACKError):
            decoder.decode(b"\x80")
        with self.assertRaises(HPACKError):
            decoder.decode(b"\x40\x05ab")


if __name__ == "__main__":
    unittest.main()
