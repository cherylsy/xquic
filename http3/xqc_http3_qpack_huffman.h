#ifndef XQC_HTTP3_QPACK_HUFFMAN_H
#define XQC_HTTP3_QPACK_HUFFMAN_H


typedef struct {
  /* The number of bits in this code */
  uint32_t nbits;
  /* Huffman code aligned to LSB */
  uint32_t code;
} xqc_http3_qpack_huffman_sym;

extern const xqc_http3_qpack_huffman_sym xqc_g_huffman_sym_table[];

size_t xqc_http3_qpack_huffman_encode_count(const uint8_t *src, size_t len);

uint8_t *xqc_http3_qpack_huffman_encode(uint8_t *dest, const uint8_t *src,
                                      size_t srclen);

typedef enum {
  /* FSA accepts this state as the end of huffman encoding
     sequence. */
  XQC_HTTP3_QPACK_HUFFMAN_ACCEPTED = 1,
  /* This state emits symbol */
  XQC_HTTP3_QPACK_HUFFMAN_SYM = (1 << 1),
  /* If state machine reaches this state, decoding fails. */
  XQC_HTTP3_QPACK_HUFFMAN_FAIL = (1 << 2)
} xqc_http3_qpack_huffman_decode_flag;

typedef struct {
  /* huffman decoding state, which is actually the node ID of internal
     huffman tree.  We have 257 leaf nodes, but they are identical to
     root node other than emitting a symbol, so we have 256 internal
     nodes [1..255], inclusive. */
  uint8_t state;
  /* bitwise OR of zero or more of the
     xqc_http3_qpack_huffman_decode_flag */
  uint8_t flags;
  /* symbol if XQC_HTTP3_QPACK_HUFFMAN_SYM flag set */
  uint8_t sym;
} xqc_http3_qpack_huffman_decode_node;

typedef struct {
  /* Current huffman decoding state. We stripped leaf nodes, so the
     value range is [0..255], inclusive. */
  uint8_t state;
  /* nonzero if we can say that the decoding process succeeds at this
     state */
  uint8_t accept;
} xqc_http3_qpack_huffman_decode_context;

extern const xqc_http3_qpack_huffman_decode_node xqc_g_qpack_huffman_decode_table[][16];

void xqc_http3_qpack_huffman_decode_context_init(xqc_http3_qpack_huffman_decode_context *ctx);

/*
 * xqc_http3_qpack_huffman_decode decodes huffman encoded byte string
 * stored in |src| of length |srclen|.  |ctx| is a decoding context.
 * |ctx| remembers the decoding state, and caller can call this
 * function multiple times to feed each chunk of huffman encoded
 * substring.  |fin| must be nonzero if |src| contains the last chunk
 * of huffman string.  The decoded string is written to the buffer
 * pointed by |dest|.  This function assumes that the buffer pointed
 * by |dest| contains enough memory to store decoded byte string.
 *
 * This function returns the number of bytes written to |dest|, or one
 * of the following negative error codes:
 *
 * XQC_HTTP3_ERR_QPACK_FATAL
 *     Could not decode huffman string.
 */
ssize_t xqc_http3_qpack_huffman_decode(xqc_http3_qpack_huffman_decode_context *ctx,
                                     uint8_t *dest, const uint8_t *src,
                                     size_t srclen, int fin);

#endif /* XQC_HTTP3_QPACK_HUFFMAN_H */
