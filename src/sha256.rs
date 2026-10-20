/// https://en.wikipedia.org/wiki/SHA-2#Pseudocode
pub fn digest(message: &[u8], out: &mut [u8; 32]) {
    let mut hash: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    // Padding
    let input_bits = message.len() * 8;
    let padded_len_bits = (input_bits + 1 + 64).next_multiple_of(512);
    let padding_zeros = padded_len_bits - input_bits - 1 - 64;

    debug_assert!(padding_zeros >= 8);
    debug_assert!(padding_zeros % 8 == 7);

    let mut input = Vec::with_capacity(padded_len_bits / 8);
    input.extend_from_slice(message);
    input.push(0b1000_0000);
    input.extend(std::iter::repeat_n(0x00, padding_zeros / 8));
    input.extend(u64::try_from(message.len() * 8).unwrap().to_be_bytes());

    debug_assert!(input.len() % 64 == 0);

    for chunk in input.as_chunks::<64>().0 {
        let mut w = [0u32; 64];

        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[4 * i..][..4].try_into().unwrap());
        }

        for i in 16..64 {
            // s0 := (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
            let s0 = (w[i - 15].rotate_right(7)) ^ (w[i - 15].rotate_right(18)) ^ (w[i - 15] >> 3);
            // s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
            let s1 = (w[i - 2].rotate_right(17)) ^ (w[i - 2].rotate_right(19)) ^ (w[i - 2] >> 10);
            // w[i] := w[i-16] + s0 + w[i-7] + s1
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1)
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = hash;

        for i in 0..64 {
            // S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
            let s1 = (e.rotate_right(6)) ^ (e.rotate_right(11)) ^ (e.rotate_right(25));
            // ch := (e and f) xor ((not e) and g)
            let ch = (e & f) ^ (!e & g);
            // temp1 := h + S1 + ch + k[i] + w[i]
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k[i])
                .wrapping_add(w[i]);
            // S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
            let s0 = (a.rotate_right(2)) ^ (a.rotate_right(13)) ^ (a.rotate_right(22));
            // maj := (a and b) xor (a and c) xor (b and c)
            let maj = (a & b) ^ (a & c) ^ (b & c);
            // temp2 := S0 + maj
            let temp2 = s0.wrapping_add(maj);

            // h := g
            h = g;
            // g := f
            g = f;
            // f := e
            f = e;
            // e := d + temp1
            e = d.wrapping_add(temp1);
            // d := c
            d = c;
            // c := b
            c = b;
            // b := a
            b = a;
            // a := temp1 + temp2
            a = temp1.wrapping_add(temp2);
        }

        hash[0] = hash[0].wrapping_add(a);
        hash[1] = hash[1].wrapping_add(b);
        hash[2] = hash[2].wrapping_add(c);
        hash[3] = hash[3].wrapping_add(d);
        hash[4] = hash[4].wrapping_add(e);
        hash[5] = hash[5].wrapping_add(f);
        hash[6] = hash[6].wrapping_add(g);
        hash[7] = hash[7].wrapping_add(h);
    }

    let (chunks, rest) = out.as_chunks_mut();
    debug_assert!(rest.is_empty());
    for (out, h) in chunks.iter_mut().zip(hash) {
        *out = h.to_be_bytes();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty() {
        let mut out = [0; 32];
        digest(b"", &mut out);
        assert_eq!(
            out,
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55
            ]
        );
    }
    #[test]
    fn quick_brown() {
        let mut out = [0; 32];
        digest(b"The quick brown fox jumps over the lazy dog", &mut out);
        assert_eq!(
            out,
            [
                0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94, 0x69, 0xca, 0x9a, 0xbc, 0xb0, 0x08,
                0x2e, 0x4f, 0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76, 0x2d, 0x02, 0xd0, 0xbf,
                0x37, 0xc9, 0xe5, 0x92
            ]
        );

        digest(b"The quick brown fox jumps over the lazy dog.", &mut out);
        assert_eq!(
            out,
            [
                0xef, 0x53, 0x7f, 0x25, 0xc8, 0x95, 0xbf, 0xa7, 0x82, 0x52, 0x65, 0x29, 0xa9, 0xb6,
                0x3d, 0x97, 0xaa, 0x63, 0x15, 0x64, 0xd5, 0xd7, 0x89, 0xc2, 0xb7, 0x65, 0x44, 0x8c,
                0x86, 0x35, 0xfb, 0x6c
            ]
        );
    }
}
