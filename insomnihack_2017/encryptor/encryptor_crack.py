#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------

# To properly copy the key, set a breakpoint to the `encrypt` at 401570h and then type
# the following to IDA python window:
#
# key = [ida_bytes.get_word(get_reg_value('rdx') + i) for i in range(0, 0x680, 2)]
# for i in range(0, len(key), 8): print(', '.join(f'0x{key[i+j]:04x}' for j in range(8)) + ',')
key_debug = [
    0xc516, 0x6ffd, 0xc52a, 0x6ffd, 0xc501, 0x6ffd, 0xc552, 0x41e5,
    0x8948, 0x55f8, 0x72ff, 0x41e0, 0xe483, 0x4808, 0x2454, 0x8dcc,
    0xebed, 0xc560, 0x626f, 0xfdc5, 0xf1f9, 0xcdc5, 0xdb75, 0xfdc5,
    0xd9d9, 0xcdc5, 0xf5d5, 0xedc5, 0xcde4, 0xedc5, 0x6046, 0x6f7d,
    0xc5f0, 0x75cd, 0xc5de, 0xfde5, 0xc50f, 0xd371, 0xe5c5, 0xe4eb,
    0xbdc5, 0xccd5, 0x3dc5, 0xfce4, 0xbdc5, 0x405e, 0x6f7d, 0xc5d5,
    0x566f, 0xfdc5, 0xeedb, 0xedc5, 0x0000, 0x00c0, 0xaa6f, 0x7dc5,
    0xc875, 0xf5c5, 0x405a, 0xfd25, 0xc5cf, 0xf935, 0xc5cf, 0xd9b5,
    0xeff1, 0x4e56, 0x3864, 0x30c1, 0xba98, 0xd7e2, 0x1ab0, 0x5ffb,
    0x4d1d, 0x7ae6, 0x0ee3, 0xfdb5, 0xdc2e, 0x54a2, 0x7217, 0xffd1,
    0xf021, 0x6b61, 0x62e3, 0x4c81, 0xb3b3, 0xf125, 0x3bb0, 0x71c3,
    0x7245, 0x05af, 0x8975, 0xbac1, 0xbcc6, 0x73b3, 0x77f9, 0xeed0,
    0x4f1d, 0x8393, 0x7f68, 0xa5ae, 0xa98f, 0x5317, 0x9faa, 0x376c,
    0x6358, 0x05d0, 0x409c, 0x8e49, 0xfea1, 0x24d9, 0x6111, 0xbbd1,
    0xd9ad, 0xe576, 0xa646, 0x2f8b, 0x70d8, 0x5906, 0xb643, 0xb5a1,
    0x57ce, 0x30d9, 0xfe71, 0xb3a9, 0xdcba, 0xed4b, 0x1d5e, 0x1b75,
    0x22e3, 0xcb00, 0x222f, 0x71bd, 0xcbfa, 0xe9ea, 0x85f3, 0xa763,
    0xf56c, 0x5f85, 0x318c, 0x1be2, 0x2cdd, 0x7119, 0xb383, 0x3832,
    0x4e76, 0x981f, 0x25da, 0x5378, 0xce28, 0xea8d, 0x3506, 0xfab0,
    0x94f7, 0x9715, 0x24bd, 0x0076, 0x0a3b, 0x415f, 0xf7c9, 0x4420,
    0x251a, 0xe66c, 0xaf5a, 0x5749, 0x8412, 0x69a5, 0x1ad9, 0xaaab,
    0xbdd8, 0xcff1, 0xf902, 0x7df0, 0x277c, 0x312a, 0xb950, 0xf069,
    0x93b5, 0xa486, 0x3a6e, 0xbb24, 0x9285, 0x4e5f, 0x8a74, 0x80d5,
    0x3334, 0xfc46, 0x64ce, 0x3f22, 0x4c85, 0x00b0, 0x5ab2, 0x1ead,
    0xf781, 0x578b, 0xee2b, 0x273b, 0x6289, 0xe8f6, 0x9e55, 0x5b1a,
    0x3f45, 0x6c7a, 0x847b, 0x6f31, 0x13bf, 0xf4c7, 0x336d, 0x13b1,
    0xca85, 0x6f13, 0x3e8a, 0x5ca8, 0x5281, 0x1c15, 0x9d8b, 0x0de6,
    0xbf75, 0x1673, 0x1f5a, 0x35fa, 0x80dd, 0x4e30, 0x15a1, 0x280d,
    0x6897, 0x5b9c, 0xb1e9, 0x0d3d, 0x9d00, 0x1017, 0x9e8f, 0xcaa6,
    0xf643, 0xfe9e, 0x3519, 0xd769, 0x35e5, 0xaf2f, 0x50d2, 0x8536,
    0x8c66, 0xe6ca, 0x8a4d, 0x5dd9, 0x0264, 0xf425, 0xd944, 0xa9ed,
    0x60a8, 0x82dd, 0x1acc, 0x74b1, 0xf034, 0xa4d7, 0xa777, 0xae9e,
    0x07a5, 0x87e0, 0x24f0, 0x1c4a, 0x0141, 0xfa1e, 0x94b6, 0x2e29,
    0x34b9, 0x3418, 0x7a3f, 0x559c, 0x7bfb, 0xd39e, 0x6ba9, 0xbd95,
    0x6bbd, 0xd6f6, 0xf072, 0xa35d, 0xda1f, 0x1e3e, 0x9098, 0x571c,
    0x3510, 0x4832, 0x85fb, 0x1d0b, 0xccac, 0xe1e6, 0xa1c9, 0xf8cb,
    0x3546, 0x9f6e, 0x7258, 0xca77, 0x94e5, 0x17b6, 0x5b78, 0x9f9f,
    0xc499, 0x2a27, 0xd8c2, 0x9209, 0xd0e0, 0xd689, 0x5546, 0x3b18,
    0x8f4e, 0x5eff, 0x4666, 0x0832, 0xa624, 0x1480, 0x96d0, 0x8798,
    0xb99a, 0x4f2b, 0x5f61, 0xbbad, 0x148e, 0x3150, 0xed30, 0x238b,
    0xd0aa, 0x7d4e, 0xadb1, 0xfe12, 0x0b85, 0x5b5f, 0x5a43, 0xb162,
    0x6a51, 0x248b, 0x771a, 0x0faf, 0xebf2, 0x9b6f, 0x5691, 0x328d,
    0x97e4, 0x65a0, 0xc066, 0x748c, 0xfd2e, 0xd5f8, 0xb287, 0xcfeb,
    0xbd92, 0xa8de, 0xba73, 0x2346, 0xba30, 0x7188, 0xca77, 0x45a2,
    0xc28a, 0x1d7f, 0xd1fd, 0x51ab, 0x74a6, 0x68dc, 0x4a8a, 0x922b,
    0x3191, 0xd9ef, 0x6f92, 0x53b9, 0x8f0d, 0x58ca, 0x58bc, 0xe06f,
    0xe510, 0xe0bf, 0xb4f3, 0x8d39, 0x8b8f, 0x3ca5, 0xc396, 0xce3c,
    0x3542, 0x8c49, 0x1b0b, 0x8b8d, 0xa55e, 0xe0e4, 0x408b, 0x8e4f,
    0x7f9b, 0x6f3b, 0x9ebb, 0x8ab8, 0x0b56, 0x833a, 0x3541, 0x1439,
    0x47bc, 0x7cbd, 0xff19, 0x96b5, 0x9b36, 0xd20b, 0xa250, 0x351c,
    0x7ad1, 0x72c4, 0x69d2, 0x33de, 0x7d7e, 0x634f, 0x45b6, 0xc2d7,
    0x0400, 0x066a, 0x346b, 0x6c22, 0x9d7c, 0x1e93, 0xe5dc, 0x4ebf,
    0xcf57, 0xd58c, 0xa1de, 0x7ce1, 0xc83d, 0x876e, 0xa2cf, 0x27e5,
    0x99c7, 0x6a8d, 0xce79, 0x2b88, 0x1d0f, 0xfecd, 0x79ff, 0x36d2,
    0xef78, 0xd729, 0xb2a7, 0x2133, 0xf2cf, 0xe932, 0x9276, 0xa43f,
    0xb451, 0x3367, 0x8082, 0x9291, 0x860b, 0xe2c5, 0xefe3, 0x3b8d,
    0xab3c, 0x3339, 0x4bb5, 0x2454, 0x3633, 0xcca9, 0xbb4a, 0x19c0,
    0x541a, 0x4ee9, 0xb3b5, 0x9589, 0xeb88, 0x7a38, 0xea58, 0x6a9f,
    0x3c2e, 0x2dba, 0x5197, 0x0fa0, 0x3bfe, 0xa232, 0xacff, 0xe09f,
    0x65a2, 0x8061, 0xc1a1, 0xae78, 0xf6e5, 0x609f, 0xb39b, 0xbce7,
    0x7508, 0xf3a7, 0xb482, 0xf5ab, 0x5853, 0xa339, 0x616c, 0x1ddd,
    0x224a, 0xfdd8, 0x2913, 0x2cf2, 0x09ae, 0x1bf6, 0xdcae, 0xcd42,
    0x51e7, 0x7bea, 0xc12c, 0xf0c2, 0x9f50, 0x8f54, 0x1603, 0xf044,
    0xfce4, 0xea2d, 0xdd5d, 0x54a7, 0x22a6, 0x517c, 0x30e6, 0xf248,
    0x01ba, 0x240f, 0x2b8d, 0xcdb7, 0x6821, 0x11c9, 0x8f94, 0x071a,
    0xdd69, 0x381a, 0xa7a9, 0x58c3, 0x69b5, 0x2afe, 0xa098, 0x6a40,
    0x3d0d, 0xafaf, 0x3882, 0xdeab, 0xe715, 0xeaaf, 0x9a8e, 0x5424,
    0xdbe9, 0xabc0, 0x0ffd, 0x842c, 0xf54e, 0xba40, 0x7e4d, 0x0f02,
    0x8c0d, 0x36de, 0x754b, 0x0633, 0xe516, 0xa9b9, 0x41de, 0xdd3e,
    0x48ac, 0x1591, 0x5794, 0xd040, 0x1864, 0xa800, 0xf3b1, 0xe376,
    0x1282, 0x5a55, 0xd02e, 0x6f39, 0xbd7f, 0x8a16, 0x5064, 0x1ab6,
    0xe168, 0x9fbb, 0x41d5, 0x37e8, 0xf96b, 0xf3e0, 0x6bb0, 0x33dc,
    0x49ae, 0x6a92, 0x239b, 0xf564, 0x5db0, 0x4e98, 0x66f1, 0x5340,
    0x48ef, 0xb55b, 0xd6c9, 0x8867, 0xcd68, 0xac6b, 0x99e9, 0x3582,
    0x1cfb, 0x1fa1, 0x5abd, 0xf967, 0x271d, 0xeb35, 0x78ea, 0x1958,
    0x246f, 0x167f, 0xbdc6, 0x9019, 0xafd9, 0x1dd6, 0xf023, 0x2ff1,
    0x6c8a, 0x0576, 0xacb0, 0x494c, 0xca2a, 0x73e8, 0xcf6c, 0xeab4,
    0xc78f, 0x5424, 0x23b7, 0xab81, 0xa694, 0xd82f, 0x7a8e, 0xb967,
    0x3637, 0x9c26, 0xc02d, 0x7da4, 0x48c4, 0x891e, 0x10ef, 0xd384,
    0xad64, 0x7258, 0xabeb, 0x771e, 0xda11, 0x5b7c, 0x6e39, 0xe6d6,
    0x6f59, 0x79d1, 0xfb0d, 0x5920, 0x87c1, 0xc44b, 0xd59a, 0x2e86,
    0x8ee5, 0x6e37, 0xe5c2, 0x7e08, 0x02df, 0x3ecd, 0x2de6, 0x1cea,
    0xb8c6, 0x4eaf, 0x07f4, 0xe668, 0xf991, 0xbef4, 0xd6d6, 0xe940,
    0xbe1b, 0x08e3, 0x1f7b, 0x2097, 0x38e9, 0x0aca, 0x84b4, 0x3fad,
    0x5f5e, 0xbf37, 0xb216, 0xa9f5, 0xc6f4, 0x9f9e, 0xf5d1, 0xb2ca,
    0xb5df, 0x24c7, 0x9956, 0xd27c, 0xdc44, 0xf106, 0xcc03, 0xf6c9,
    0xd208, 0x30ec, 0xeda0, 0x98b9, 0x449c, 0xf794, 0xeb5e, 0x256d,
    0x1a4d, 0x3209, 0x05af, 0x0787, 0x4290, 0xa8c7, 0x431e, 0x3a9a,
    0xaf67, 0x488a, 0xd9a2, 0x41c2, 0xce5c, 0xc255, 0x7ed8, 0x9e10,
    0x8156, 0x689c, 0x2906, 0x84c8, 0x43f6, 0x0f94, 0x0f4c, 0x4642,
    0x43c0, 0x2e2a, 0xa407, 0xe11c, 0x2748, 0x3d61, 0x3fdc, 0x590e,
    0xf0f4, 0xd574, 0xd4ba, 0xe76a, 0x6553, 0xb22a, 0x3959, 0x61d6,
    0x951d, 0xa68e, 0xfd1e, 0x5498, 0x0b6a, 0x4c5a, 0x92fe, 0xd737,
    0xe80d, 0x8ebd, 0x93b8, 0x0419, 0xf9ec, 0xc433, 0x0454, 0x759e,
    0x307e, 0xc845, 0x0fda, 0x8e90, 0x8419, 0x7f64, 0xc566, 0x33ef,
    0xe4f4, 0x0ade, 0xc972, 0xb2bd, 0x4225, 0x4483, 0xb339, 0xcdc5,
    0xf4f6, 0x7d73, 0xfa86, 0xc527, 0x2e33, 0xd820, 0x2112, 0xf60b,
    0x00ac, 0x8a27, 0xd605, 0xf608, 0xf613, 0x1691, 0xa362, 0x341e,
    0x6c91, 0xc4c4, 0xdeb4, 0xb57d, 0x8bfe, 0x8935, 0xd95e, 0xf170,
    0x597f, 0x8990, 0x043a, 0xea7b, 0x388f, 0xa120, 0xf666, 0xef5b,
    0xe8e9, 0xc9aa, 0x6656, 0x93bc, 0xaea1, 0x99e4, 0x0d81, 0x9b14,
    0x35c0, 0xbf44, 0x0a9e, 0x0037, 0x6bdd, 0xbd3b, 0x5bbb, 0xad37,
    0xc92a, 0x07a0, 0xd2f8, 0xe6e9, 0xe9ff, 0x471d, 0xcab1, 0x9537,
    0xfa15, 0x0b70, 0x2771, 0x1584, 0x4441, 0xd2b2, 0x8e68, 0x130d,
]

# There is an anti debugging check that computes a different key
# if you set breakpoints inside encrypt. This is the real key.
key_real = [
    0xc516, 0x6ffd, 0xc52a, 0x6ffd, 0xc501, 0x6ffd, 0xc552, 0x41e5,
    0x8948, 0x55f8, 0x72ff, 0x41e0, 0xe483, 0x4808, 0x2454, 0x8d4c,
    0xebed, 0xc560, 0x626f, 0xfdc5, 0xf1f9, 0xcdc5, 0xdb75, 0xfdc5,
    0xd9d9, 0xcdc5, 0xf5d5, 0xedc5, 0xcde4, 0xedc5, 0x6046, 0x6f7d,
    0xc5f0, 0x75cd, 0xc5de, 0xfde5, 0xc50f, 0xd371, 0xe5c5, 0xe4eb,
    0xbdc5, 0xccd5, 0x3dc5, 0xfce4, 0xbdc5, 0x405e, 0x6f7d, 0xc5d5,
    0x566f, 0xfdc5, 0xeedb, 0xedc5, 0x0000, 0x00c0, 0xaa6f, 0x7dc5,
    0xc875, 0xf5c5, 0x405a, 0xfd25, 0xc5cf, 0xf935, 0xc5cf, 0xd9b5,
    0xeff1, 0x4e56, 0x3864, 0x30c1, 0xba98, 0xd7e2, 0x1ab0, 0x5ffb,
    0x4d1d, 0x7ae6, 0x0ee3, 0xfdb5, 0xdc2e, 0x54a2, 0x6217, 0xffd1,
    0xf021, 0x6b61, 0x62e3, 0x4c81, 0xb3b3, 0xf125, 0x3bb0, 0x71c3,
    0x7245, 0x05af, 0x8975, 0xbac1, 0xbcc6, 0x73b1, 0x77f9, 0xeed0,
    0x4f1d, 0x8393, 0x7f68, 0xa5ae, 0xa98f, 0x5317, 0x9faa, 0x376c,
    0x6358, 0x05d0, 0x409c, 0x8e49, 0xfd61, 0x24c7, 0x6111, 0xbbd1,
    0xd9ad, 0xe576, 0xa646, 0x2f8b, 0x70d8, 0x5906, 0xb643, 0xb5a1,
    0x57ce, 0x30d9, 0xfe71, 0xb3a9, 0xdb3a, 0xed4b, 0x1d5e, 0xb374,
    0x22e3, 0xcb00, 0x222f, 0x71bd, 0xcbfa, 0xe9ea, 0x85f3, 0xa763,
    0xf56c, 0x5f85, 0x318c, 0x1be2, 0x229d, 0x711f, 0xb3f6, 0x502d,
    0x4e76, 0x981f, 0x25da, 0x5378, 0xce28, 0xea8d, 0x3506, 0xfab0,
    0x94f7, 0x9715, 0x24bd, 0x0076, 0x0bbb, 0x57ff, 0xf319, 0xec22,
    0x251a, 0xe66c, 0xaf5a, 0x5749, 0x8412, 0x69a5, 0x1ad9, 0xaaab,
    0xbdd8, 0xcff1, 0xf902, 0x7df0, 0x7e7a, 0xc58b, 0xb922, 0xf06e,
    0x93b5, 0xa486, 0x3a6e, 0xbb24, 0x9285, 0x4e5f, 0x8a74, 0x80d5,
    0x3334, 0xfc46, 0x64ce, 0x3f22, 0xe376, 0x88f1, 0x5ab2, 0xc1fb,
    0xf781, 0x578b, 0xee2b, 0x273b, 0x6289, 0xe8f6, 0x9e55, 0x5b1a,
    0x3f45, 0x6c7a, 0x847b, 0x6f31, 0xa6fc, 0xe827, 0x9aff, 0xe589,
    0xca85, 0x6f13, 0x3e8a, 0x5ca8, 0x5281, 0x1c15, 0x9d8b, 0x0de6,
    0xbf75, 0x1673, 0x1f5a, 0x35fa, 0x50e2, 0x37eb, 0xa6b6, 0xfe93,
    0x6897, 0x5b9c, 0xb1e9, 0x0d3d, 0x9d00, 0x1017, 0x9e8f, 0xcaa6,
    0xf643, 0xfe9e, 0x3519, 0xd769, 0x1930, 0xf684, 0x42b1, 0x5bbb,
    0x8c66, 0xe6ca, 0x8a4d, 0x5dd9, 0x0264, 0xf425, 0xd944, 0xa9ed,
    0x60a8, 0x82dd, 0x1acc, 0x74b1, 0x85dd, 0x73c4, 0xc81c, 0x8c28,
    0x07a5, 0x87e0, 0x24f0, 0x1c4a, 0x0141, 0xfa1e, 0x94b6, 0x2e29,
    0x34b9, 0x3418, 0x7a3f, 0x559c, 0xd0f6, 0xfc90, 0x8c99, 0x19b1,
    0x6bbd, 0xd6f6, 0xf072, 0xa35d, 0xda1f, 0x1e3e, 0x9098, 0x571c,
    0x3510, 0x4832, 0x85fb, 0x1d0b, 0x7be3, 0x077c, 0x4e4f, 0x2db6,
    0x3546, 0x9f6e, 0x7258, 0xca77, 0x94e5, 0x17b6, 0x5b78, 0x9f9f,
    0xc499, 0x2a27, 0xd8c2, 0x9209, 0x4d19, 0x7cf1, 0xd0d0, 0xeab0,
    0x8f4e, 0x5eff, 0x4666, 0x0832, 0xa624, 0x1480, 0x96d0, 0x8798,
    0xb99a, 0x4f2b, 0x5f61, 0xbbad, 0x4a26, 0xad6e, 0xaed3, 0x077e,
    0xd0aa, 0x7d4e, 0xadb1, 0xfe12, 0x0b85, 0x5b5f, 0x5a43, 0xb162,
    0x6a51, 0x248b, 0x771a, 0x0faf, 0x1cfc, 0x83ca, 0x5fab, 0xc519,
    0x97e4, 0x65a0, 0xc066, 0x748c, 0xfd2e, 0xd5f8, 0xb287, 0xcfeb,
    0xbd92, 0xa8de, 0xba73, 0x2346, 0x8583, 0xf66c, 0x75f4, 0x1093,
    0xc28a, 0x1d7f, 0xd1fd, 0x51ab, 0x74a6, 0x68dc, 0x4a8a, 0x922b,
    0x3191, 0xd9ef, 0x6f92, 0x53b9, 0x0de4, 0x7974, 0x97dd, 0x8af9,
    0xe510, 0xe0bf, 0xb4f3, 0x8d39, 0x8b8f, 0x3ca5, 0xc396, 0xce3c,
    0x3542, 0x8c49, 0x1b0b, 0x8b8d, 0x91dc, 0x00c1, 0xb319, 0x909c,
    0x7f9b, 0x6f3b, 0x9ebb, 0x8ab8, 0x0b56, 0x833a, 0x3541, 0x1439,
    0x47bc, 0x7cbd, 0xff19, 0x96b5, 0x9e73, 0x9936, 0x0bbf, 0xe2b4,
    0x7ad1, 0x72c4, 0x69d2, 0x33de, 0x7d7e, 0x634f, 0x45b6, 0xc2d7,
    0x0400, 0x066a, 0x346b, 0x6c22, 0x12e2, 0x2440, 0x5c13, 0x3bb2,
    0xcf57, 0xd58c, 0xa1de, 0x7ce1, 0xc83d, 0x876e, 0xa2cf, 0x27e5,
    0x99c7, 0x6a8d, 0xce79, 0x2b88, 0xdcd2, 0xf97c, 0x7b91, 0x2d10,
    0xef78, 0xd729, 0xb2a7, 0x2133, 0xf2cf, 0xe932, 0x9276, 0xa43f,
    0xb451, 0x3367, 0x8082, 0x9291, 0xae2f, 0x9ba2, 0x23bc, 0x7c2c,
    0xab3c, 0x3339, 0x4bb5, 0x2454, 0x3633, 0xcca9, 0xbb4a, 0x19c0,
    0x541a, 0x4ee9, 0xb3b5, 0x9589, 0x9af2, 0xfef4, 0x3329, 0x86d9,
    0x3c2e, 0x2dba, 0x5197, 0x0fa0, 0x3bfe, 0xa232, 0xacff, 0xe09f,
    0x65a2, 0x8061, 0xc1a1, 0xae78, 0xd223, 0xd2b2, 0x74d7, 0xe4fe,
    0x7508, 0xf3a7, 0xb482, 0xf5ab, 0x5853, 0xa339, 0x616c, 0x1ddd,
    0x224a, 0xfdd8, 0x2913, 0x2cf2, 0x40a8, 0xc188, 0x5eda, 0x1f6d,
    0x51e7, 0x7bea, 0xc12c, 0xf0c2, 0x9f50, 0x8f54, 0x1603, 0xf044,
    0xfce4, 0xea2d, 0xdd5d, 0x54a7, 0x8368, 0xcbde, 0x41d9, 0x3640,
    0x01ba, 0x240f, 0x2b8d, 0xcdb7, 0x6821, 0x11c9, 0x8f94, 0x071a,
    0xdd69, 0x381a, 0xa7a9, 0x58c3, 0x58a3, 0xfe32, 0x636e, 0x7991,
    0x3d0d, 0xafaf, 0x3882, 0xdeab, 0xe715, 0xeaaf, 0x9a8e, 0x5424,
    0xdbe9, 0xabc0, 0x0ffd, 0x842c, 0x8522, 0xf523, 0x164e, 0x8cdb,
    0x8c0d, 0x36de, 0x754b, 0x0633, 0xe516, 0xa9b9, 0x41de, 0xdd3e,
    0x48ac, 0x1591, 0x5794, 0xd040, 0xd55b, 0x473d, 0xcb55, 0xf479,
    0x1282, 0x5a55, 0xd02e, 0x6f39, 0xbd7f, 0x8a16, 0x5064, 0x1ab6,
    0xe168, 0x9fbb, 0x41d5, 0x37e8, 0xce2d, 0xdc3c, 0x813d, 0x5b61,
    0x49ae, 0x6a92, 0x239b, 0xf564, 0x5db0, 0x4e98, 0x66f1, 0x5340,
    0x48ef, 0xb55b, 0xd6c9, 0x8867, 0xc7d5, 0xc249, 0xd68c, 0x60fa,
    0x1cfb, 0x1fa1, 0x5abd, 0xf967, 0x271d, 0xeb35, 0x78ea, 0x1958,
    0x246f, 0x167f, 0xbdc6, 0x9019, 0x9a7a, 0x48b4, 0xcbe6, 0x3955,
    0x6c8a, 0x0576, 0xacb0, 0x494c, 0xca2a, 0x73e8, 0xcf6c, 0xeab4,
    0xc78f, 0x5424, 0x23b7, 0xab81, 0xd4e2, 0x90a6, 0xff6b, 0xc315,
    0x3637, 0x9c26, 0xc02d, 0x7da4, 0x48c4, 0x891e, 0x10ef, 0xd384,
    0xad64, 0x7258, 0xabeb, 0x771e, 0x476a, 0x30d5, 0x0294, 0xb4e1,
    0x6f59, 0x79d1, 0xfb0d, 0x5920, 0x87c1, 0xc44b, 0xd59a, 0x2e86,
    0x8ee5, 0x6e37, 0xe5c2, 0x7e08, 0x8256, 0x0579, 0x5c85, 0x6977,
    0xb8c6, 0x4eaf, 0x07f4, 0xe668, 0xf991, 0xbef4, 0xd6d6, 0xe940,
    0xbe1b, 0x08e3, 0x1f7b, 0x2097, 0x3e49, 0x4bf0, 0x1af7, 0x2f96,
    0x5f5e, 0xbf37, 0xb216, 0xa9f5, 0xc6f4, 0x9f9e, 0xf5d1, 0xb2ca,
    0xb5df, 0x24c7, 0x9956, 0xd27c, 0xf3fa, 0x312b, 0x05dd, 0x7d70,
    0xd208, 0x30ec, 0xeda0, 0x98b9, 0x449c, 0xf794, 0xeb5e, 0x256d,
    0x1a4d, 0x3209, 0x05af, 0x0787, 0x57cf, 0x3d07, 0x9e68, 0x8663,
    0xaf67, 0x488a, 0xd9a2, 0x41c2, 0xce5c, 0xc255, 0x7ed8, 0x9e10,
    0x8156, 0x689c, 0x2906, 0x84c8, 0x94cb, 0x49aa, 0x38e2, 0xe658,
    0x43c0, 0x2e2a, 0xa407, 0xe11c, 0x2748, 0x3d61, 0x3fdc, 0x590e,
    0xf0f4, 0xd574, 0xd4ba, 0xe76a, 0x4dc1, 0x5f4b, 0xae45, 0x9e01,
    0x951d, 0xa68e, 0xfd1e, 0x5498, 0x0b6a, 0x4c5a, 0x92fe, 0xd737,
    0xe80d, 0x8ebd, 0x93b8, 0x0419, 0xa0b1, 0xdfaf, 0x9156, 0xb4eb,
    0x307e, 0xc845, 0x0fda, 0x8e90, 0x8419, 0x7f64, 0xc566, 0x33ef,
    0xe4f4, 0x0ade, 0xc972, 0xb2bd, 0x9f8e, 0xe084, 0xb955, 0x73c9,
    0xf4f6, 0x7d73, 0xfa86, 0xc527, 0x2e33, 0xd820, 0x2112, 0xf60b,
    0x00ac, 0x8a27, 0xd605, 0xf608, 0x04e3, 0x6e0b, 0xc84b, 0x3d34,
    0x6c91, 0xc4c4, 0xdeb4, 0xb57d, 0x8bfe, 0x8935, 0xd95e, 0xf170,
    0x597f, 0x8990, 0x043a, 0xea7b, 0x27d0, 0xe3ca, 0x5800, 0x55fc,
    0xe8e9, 0xc9aa, 0x6656, 0x93bc, 0xaea1, 0x99e4, 0x0d81, 0x9b14,
    0x35c0, 0xbf44, 0x0a9e, 0x0037, 0x5147, 0x3b9b, 0x4ea1, 0xcb70,
    0xc92a, 0x07a0, 0xd2f8, 0xe6e9, 0xe9ff, 0x471d, 0xcab1, 0x9537,
    0xfa15, 0x0b70, 0x2771, 0x1584, 0xc265, 0xf120, 0x5163, 0x90df,
]


# To get the "unknown" vectors:
# 
# [ida_bytes.get_word(get_reg_value('rcx') + $OFF + i) for i in range(0, 0x20, 2)]
# Where $OFF is 0, 0x20, 0x40, 0x200, 0x220, 0x240
unkn = [
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
]
unkn_20 = [
    0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000,
    0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000
]
unkn_40 = [
    0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
    0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d
]

# The vectors below are used for shuffling
unkn_200 = [
    0x706, 0x100, 0x302, 0x504, 0xf0e, 0x908, 0xb0a, 0xd0c,
    0x706, 0x100, 0x302, 0x504, 0xf0e, 0x908, 0xb0a, 0xd0c
]
unkn_220 = [
    0x504, 0x706, 0x100, 0x302, 0xd0c, 0xf0e, 0x908, 0xb0a,
    0x504, 0x706, 0x100, 0x302, 0xd0c, 0xf0e, 0x908, 0xb0a
]
unkn_240 = [
    0x302, 0x504, 0x706, 0x100, 0xb0a, 0xd0c, 0xf0e, 0x908,
    0x302, 0x504, 0x706, 0x100, 0xb0a, 0xd0c, 0xf0e, 0x908
]

# The inverse vectors used to restore shuffling.
inv_unkn_200 = unkn_240
inv_unkn_220 = unkn_220
inv_unkn_240 = unkn_200

# To get the sample plaintext:
#
# [ida_bytes.get_word(get_reg_value('rsi') + i) for i in range(0, 0x80, 2)]
plain = [
    0x3842, 0x3742, 0x3642, 0x3542, 0x3442, 0x3342, 0x3242, 0x3142,
    0x3841, 0x3741, 0x3641, 0x3541, 0x3441, 0x3341, 0x3241, 0x3141,
    0x3844, 0x3744, 0x3644, 0x3544, 0x3444, 0x3344, 0x3244, 0x3144,
    0x3843, 0x3743, 0x3643, 0x3543, 0x3443, 0x3343, 0x3243, 0x3143,
    0x3846, 0x3746, 0x3646, 0x3546, 0x3446, 0x3346, 0x3246, 0x3146,
    0x3845, 0x3745, 0x3645, 0x3545, 0x3445, 0x3345, 0x3245, 0x3145,
    0x3848, 0x3748, 0x3648, 0x3548, 0x3448, 0x3348, 0x3248, 0x3148,
    0x3847, 0x3747, 0x3647, 0x3547, 0x3447, 0x3347, 0x3247, 0x3147
]


# ----------------------------------------------------------------------------------------
def dbg(ymm):
    """Converts a `ymm` register into a 16-WORD string."""
    return ' '.join(f'{w:04X}' for w in ymm)


# ----------------------------------------------------------------------------------------
def F(v, k, d=False):
    """
    F(p01, key):
        A = ((p01 * key) & 0xFFFF) - ((p01 * key) >> 16)
        As = ((p01 * key) & 0xFFFF) - ((p01 * key) >> 16) if >0 else zero = As (SATURATED)
        Ae = if As == 0 then set to 0xFFFF else set to 0 
        Az = if A == 0 then set 0xFFFF
        (A + MSB(Ae)) - ((p01 | key) & Az) = R0 
        return R0

    This can be further simplified, but I can't figure it out right now :\
    """
    ymm1 = [(a * b) >> 16 for a, b in zip(v, k)]
    if d: print('    ymm1:', dbg(ymm1))

    ymm6 = [(a * b) & 0xFFFF for a, b in zip(v, k)]
    if d: print('    ymm6:', dbg(ymm6))

    ymm3 = [b - a if b > a else 0 for a, b in zip(ymm1, ymm6)]
    if d: print('    ymm3:', dbg(ymm3))

    ymm3 = [0 if a else 0xFFFF for a in ymm3]
    if d: print('    ymm3:', dbg(ymm3))

    A = [(b - a) & 0xFFFF for a, b in zip(ymm1, ymm6)]  # ymm6
    if d: print('    A   :', dbg(A))

    ymm2 = [a | b for a, b in zip(v, k)]
    if d: print('    ymm2:', dbg(ymm2))

    ymm3 = [a >> 15 for a in ymm3]
    if d: print('    ymm3:', dbg(ymm3))

    ymm3 = [(a + b) & 0xFFFF for a, b in zip(A, ymm3)]
    if d: print('    ymm3:', dbg(ymm3))

    ymm6 = [0 if a else 0xFFFF for a in A]
    if d: print('    ymm6:', dbg(ymm6))
   
    ymm5 = [a & b for a, b in zip(ymm2, ymm6)]
    if d: print('    ymm5:', dbg(ymm5))

    R0 = [(a - b) & 0xFFFF for a, b in zip(ymm3, ymm5)]  # ymm5
    if d: print('    R0  :', dbg(R0))

    return R0

# ----------------------------------------------------------------------------------------
def inv_F(v, k, d=False):
    """Simply brute force F."""
    def bf(vv, kk):
        for i in range(65536):
            # # This is too slow
            # if F([i], [kk]) == [vv]:
            #   return i

            # This an almost-correct implementation of F.
            if kk:
                x = (i * kk) & 0xFFFF
                y = (i * kk) >> 16
                res = (x - y) if (x > y) else ((x - y) + 0x10000 + 1)
            else:
                res = 0x10000 + 1 - i
       
            if res == vv:
                return i            

        # However sometimes it fails, so we fall back to calling F (which is slow).
        for i in range(65536):
            if F([i], [kk], 0) == [vv]:
                return i
        
    R0 = [bf(a, b) for a, b in zip(v, k)]  # ymm5
    if d: print('    R0  :', dbg(R0))

    return R0
    

# ----------------------------------------------------------------------------------------
def T(r, p, k, d=False):
    """Function for t variables. Return (p + k) ^ r."""
    t0 = [(a + b) & 0xFFFF for a, b in zip(p, k)]
    if d: print('    t0:', dbg(t0))

    t1 = [a ^ b for a, b in zip(r, t0)]
    if d: print('    t1:', dbg(t1))

    return t1


# ----------------------------------------------------------------------------------------
def S(v, d=False):
    """ 
    S(v):
        v = R2 + t1
        s1 = SHF93(R2 + t1) ^ (R2 + t1)
        Dz = s1 & 0x8000 == 0x8000 ? if yes set to 0xFFFF
        t2 = (Dz & 0x2D) ^ ((SHF93(R2 + t1) ^ (s1 << 1)) ^ SHF4E(s1))
        return t2
    """
    # SHF 93 = 1001 0011 ~> reverse ~> 11 00 01 10
    s = v[:4] + [v[7], v[4], v[5], v[6]] + v[8:12] + [v[15], v[12], v[13], v[14]]  # 0x93
    if d: print('     s:', dbg(s))

    s = [s[3], s[0], s[1], s[2]] + s[4:8] + [s[11], s[8], s[9], s[10]] + s[12:]  # 0x93
    if d: print('     s:', dbg(s))
    s93 = s[::]

    s1 = [a ^ b for a, b in zip(s, v)]
    if d: print('    t1:', dbg(s1))

    ymm9 = [(a << 1) & 0xFFFF for a in s1]
    if d: print('  ymm9:', dbg(ymm9))

    v = s1
    # SHF 4E = 0100 1110 ~> reverse ~> 10 11 00 01
    s = v[:4] + [v[6], v[7], v[4], v[5]] + v[8:12] + [v[14], v[15], v[12], v[13]]
    if d: print('     s:', dbg(s))

    s = [s[2], s[3], s[0], s[1]] + s[4:8] + [s[10], s[11], s[8], s[9]] + s[12:] 
    if d: print('     s:', dbg(s))

    ymm6 = [a ^ b for a, b in zip(s93, ymm9)]
    if d: print('  ymm6:', dbg(ymm6))

    Dz = [0xFFFF if a & 0x8000 else 0 for a in s1]
    if d: print('    Dz:', dbg(Dz))

    #  ymm3 = (SHF93(R2 + t1) ^ (s1 << 1)) ^ SHF4E(s1)
    ymm3 = [a ^ b for a, b in zip(ymm6, s)]
    if d: print('  ymm3:', dbg(ymm3))

    ymm8 = [a & 0x2D for a in Dz]
    if d: print('  ymm8:', dbg(ymm8))

    # ymm3 = (Dz & 0x2D) ^ ((SHF93(R2 + t1) ^ (s1 << 1)) ^ SHF4E(s1)) = t2
    t2 = [a ^ b for a, b in zip(ymm3, ymm8)]
    if d: print('    t2:', dbg(t2))

    return t2


# ----------------------------------------------------------------------------------------
def SHF(p, k, q, unkn, d=False):
    """
    SHF((p + k) ^ q, unkn).

    unkn is the shuffling vector.
    (p + k) ^ q is T().

    To understand shuffling (vpshufb instruction):
    https://www.intel.com/content/www/us/en/docs/cpp-compiler/developer-guide-reference/2021-8/mm256-shuffle-epi8.html
    

    Here's how shuffling works:
        5 4 7 6 1 0 3 2 D C F E 9 8 B A  (operate at byte level not at word level)
        2A82 B100 62A6 9A1A BFC7 E2CB 22E8 7F42 D4CB 9790 DF05 AFDB 730F 5237 9DED 6C89
        62A6 9A1A 2A82 B100 22E8 7F42 BFC7 E2CB DF05 AFDB D4CB 9790 9DED 6C89 730F 5237

        3 2 5 4 7 6 1 0 B A D C F E 9 8
        8A8B 3638 D6E6 DFFF 5243 9618 54EE AC78 C2B5 D50A 344F 2546 B12D 09F6 2CF4 1005
        3638 D6E6 DFFF 8A8B 9618 54EE AC78 5243 D50A 344F 2546 C2B5 09F6 2CF4 1005 B12D
    """
    t0 = [(a + b) & 0xFFFF for a, b in zip(p, k)]
    if d: print('    t0:', dbg(t0))

    t1 = [a ^ b for a, b in zip(t0, q)]
    if d: print('    t1:', dbg(t1))

    # All words in all unkn_* contain consecutive values (v << 8) | (v - 1), so we can
    # simplify things here.
    s1 = [t1[(a & 0xFF) >> 1] for a in unkn[:8]]
    s1 += [t1[8 + ((a & 0xFF) >> 1)] for a in unkn[:8]]
    if d: print('    s1:', dbg(s1))

    return s1


# ----------------------------------------------------------------------------------------
def inv_SHF(p, unkn, d=False):
    """This is like SHF, but with 1 argument."""
    t1 = p[::]
    if d: print('    t1:', dbg(t1))


    s1 = [t1[(a & 0xFF) >> 1] for a in unkn[:8]]
    s1 += [t1[8 + ((a & 0xFF) >> 1)] for a in unkn[:8]]
    if d: print('    s1:', dbg(s1))


    return s1


# ----------------------------------------------------------------------------------------
def u_encrypt(plain, key, d=False):
    """Main encryption algorithm."""
    p01 = plain[:0x10]
    p23 = plain[0x10:0x20]
    p45 = plain[0x20:0x30]
    p67 = plain[0x30:0x40]
    i = 0    

    for i in range(0, 0x600 // 2, 0xC0 // 2):
        if d: print('--------------------------- NEW ROUND: ', hex(i), hex(i<<1)) 
        if d: print('p01 :', dbg(p01))
        if d: print('p23 :', dbg(p23))
        if d: print('p45 :', dbg(p45))
        if d: print('p67 :', dbg(p67))

        R0 = F(p01, key[i:i+0x10])
        if d: print('R0  :', dbg(R0))

        t0 = T(R0, p45, key[i+0x20:i+0x30])
        if d: print('t0  :', dbg(t0))

        R1 = F(p67, key[i+0x30:i+0x40])
        if d: print('R1  :', dbg(R1))

        t1 = T(R1, p23, key[i+0x10:i+0x20])
        if d: print('t1  :', dbg(t1))
        
        R2 = F(t0, key[i+0x40:i+0x50])
        if d: print('R2  :', dbg(R2))

        R2t1 = [(a + b) & 0xFFFF for a, b in zip(R2, t1)]

        t2 = S(R2t1)
        if d: print('t2  :', dbg(t2))

        R3 = F(t2, key[i+0x50:i+0x60])
        if d: print('R3  :', dbg(R3))

        q0 = [(a + b) & 0xFFFF for a, b in zip(R2, R3)]
        if d: print('q0  :', dbg(q0))

        t4 = SHF(p23, key[i+0x10:i+0x20], q0, unkn_220)
        if d: print('t4  :', dbg(t4))

        t5 = SHF(R2, R3, R1, unkn_240)
        if d: print('t5  :', dbg(t5))

        t6 = SHF(p45, key[i+0x20:i+0x30], R3, unkn_200)
        if d: print('t6  :', dbg(t6))

        q1 = [a ^ b for a, b in zip(R0, R3)]    
        R4 = F(q1, key[i+0x60:i+0x70])
        if d: print('R4  :', dbg(R4))

        R5 = F(t5, key[i+0x90:i+0xA0])  # This is R1 of the next round
        if d: print('R5  :', dbg(R5))

        '''
        # That's round 2.

        t7 = T(R4, t4, key[i+0x80:i+0x90])
        if d: print('t7  :', dbg(t7))

        R5 = F(t5, key[i+0x90:i+0xA0])
        if d: print('R5  :', dbg(R5))

        R6 = F(t7, key[i+0xa0:i+0xb0])
        if d: print('R6  :', dbg(R6))

        t8 = T(R5, t6, key[i+0x70:i+0x80])
        if d: print('t8  :', dbg(t8))

        R6t8 = [(a + b) & 0xFFFF for a, b in zip(R6, t8)]
        t9 = S(R6t8)
        if d: print('t9  :', dbg(t9))

        R7 = F(t9, key[i+0xb0:i+0xc0])
        if d: print('R7  :', dbg(R7))

        q2 = [(a + b) & 0xFFFF for a, b in zip(R6, R7)]
        if d: print('q2  :', dbg(q2))

        t10 = SHF(R6, R7, R5, unkn_240)
        if d: print('t10 :', dbg(t10))

        t11 = SHF(t6, key[i+0x70:i+0x80], q2, unkn_220)
        if d: print('t11 :', dbg(t11))
        '''

        p01 = [a ^ b for a, b in zip(R0, R3)]
        p23 = t6[:]
        p45 = t4[:]
        p67 = t5[:] 


    # Ciphertext: 
    #   +0  ~> R4
    #   +20 ~> t6 + key620
    #   +40 ~> t4 + key640
    #   +60 ~> R5 (or R1 of next round)

    add20 = [(a + b) & 0xFFFF for a, b in zip(t6, key[0x310:0x320])]
    add40 = [(a + b) & 0xFFFF for a, b in zip(t4, key[0x320:0x330])]
    
    ciphertext = R4 + add20 + add40 + R5
    print('Ciphertext:', dbg(ciphertext))


    expected_ciphertext = [
        0x8765, 0x05DE, 0x7709, 0x0927, 0xB6FE, 0x3224, 0x9EB7, 0x8FC0,
        0xDFAB, 0x6D45, 0x0755, 0x1FD1, 0x0EF7, 0x41F9, 0x7036, 0x6BE8,
        0xD549, 0x2544, 0x43E7, 0x2034, 0x5A92, 0x0470, 0x9E45, 0x007C,
        0xC5CB, 0x66AD, 0x730F, 0xB3CA, 0xAD84, 0x4AB3, 0x231E, 0x498E,
        0x57DB, 0xB005, 0x3229, 0x28FE, 0x944F, 0xD815, 0x4543, 0xDA0B,
        0x8EEB, 0x8847, 0x6CD5, 0xF89F, 0xDFFC, 0xA0CE, 0xF859, 0x6203,
        0x5B7B, 0x776A, 0x5A7F, 0xA0E6, 0xC016, 0x007D, 0x0395, 0x1995,
        0xD811, 0x54FB, 0x8081, 0x5C21, 0x9A80, 0x7734, 0x653C, 0x555B
    ]

    assert ciphertext == expected_ciphertext
    print('ciphertexts match!!')


    # ciphertext ymm words are inverted:
    ciphertext = R4[::-1] + add20[::-1] + add40[::-1] + R5[::-1]
    '''
        .text:0000000000401076 Transform result:
        .text:0000000000401076   01 02 03 04 05 06 07 08  09 0A 0B 0C 0D 0E 0F 10
        .text:0000000000401076   11 12 13 14 15 16 17 18  19 1A 1B 1C 1D 1E 1F 20
        .text:0000000000401076   21 22 23 24 25 26 27 28  29 2A 2B 2C 2D 2E 2F 30
        .text:0000000000401076   31 32 33 34 35 36 37 38  39 3A 3B 3C 3D 3E 3F 40
        .text:0000000000401076   41 42 43 44 45 46 47 48  49 4A 4B 4C 4D 4E 4F 50
        .text:0000000000401076   51 52 53 54 55 56 57 58  59 5A 5B 5C 5D 5E 5F 60
        .text:0000000000401076   61 62 63 64 65 66 67 68  69 6A 6B 6C 6D 6E 6F 70
        .text:0000000000401076   71 72 73 74 75 76 77 78  79 7A 7B 7C 7D 7E 7F 80
        .text:0000000000401076
        .text:0000000000401076 Becomes (which is also ciphertext):
        .text:0000000000401076   1F 20 1D 1E 1B 1C 19 1A  17 18 15 16 13 14 11 12
        .text:0000000000401076   0F 10 0D 0E 0B 0C 09 0A  07 08 05 06 03 04 01 02
        .text:0000000000401076   3F 40 3D 3E 3B 3C 39 3A  37 38 35 36 33 34 31 32
        .text:0000000000401076   2F 30 2D 2E 2B 2C 29 2A  27 28 25 26 23 24 21 22
        .text:0000000000401076   5F 60 5D 5E 5B 5C 59 5A  57 58 55 56 53 54 51 52
        .text:0000000000401076   4F 50 4D 4E 4B 4C 49 4A  47 48 45 46 43 44 41 42
        .text:0000000000401076   7F 80 7D 7E 7B 7C 79 7A  77 78 75 76 73 74 71 72
        .text:0000000000401076   6F 70 6D 6E 6B 6C 69 6A  67 68 65 66 63 64 61 62
    '''

    final_ciphertext = [ 
        0x6BE8, 0x7036, 0x41F9, 0x0EF7, 0x1FD1, 0x0755, 0x6D45, 0xDFAB,
        0x8FC0, 0x9EB7, 0x3224, 0xB6FE, 0x0927, 0x7709, 0x05DE, 0x8765,
        0x498E, 0x231E, 0x4AB3, 0xAD84, 0xB3CA, 0x730F, 0x66AD, 0xC5CB,
        0x007C, 0x9E45, 0x0470, 0x5A92, 0x2034, 0x43E7, 0x2544, 0xD549,
        0x6203, 0xF859, 0xA0CE, 0xDFFC, 0xF89F, 0x6CD5, 0x8847, 0x8EEB,
        0xDA0B, 0x4543, 0xD815, 0x944F, 0x28FE, 0x3229, 0xB005, 0x57DB,
        0x555B, 0x653C, 0x7734, 0x9A80, 0x5C21, 0x8081, 0x54FB, 0xD811,
        0x1995, 0x0395, 0x007D, 0xC016, 0xA0E6, 0x5A7F, 0x776A, 0x5B7B,
    ]

    ciphertext_bytes = []
    # print as bytes
    for c in ciphertext:
        ciphertext_bytes.append(c & 0xFF)
        ciphertext_bytes.append(c >> 8)

    ciphertext_bytes += [10, 10]
    open('ciphertext.cracked', 'wb').write(bytes(ciphertext_bytes))

    return ciphertext


# ----------------------------------------------------------------------------------------
def crack(ciphertext, key, d=True):
    """Decryption algorithm"""
    if d: print('~ = ~ = ~ = CRACK = ~ = ~ = ~')

    # ciphertext = R4[::-1] + add20[::-1] + add40[::-1] + R5[::-1]
    R4    = ciphertext[:0x10][::-1]
    add20 = ciphertext[0x10:0x20][::-1]
    add40 = ciphertext[0x20:0x30][::-1]
    R5    = ciphertext[0x30:0x40][::-1]

    t6 = [(a - b) & 0xFFFF for a, b in zip(add20, key[0x310:0x320])]
    t4 = [(a - b) & 0xFFFF for a, b in zip(add40, key[0x320:0x330])]

    if d: print('R5: ', dbg(R5))
    if d: print('R4: ', dbg(R4))
    if d: print('t6: ', dbg(t6))
    if d: print('t4: ', dbg(t4))

    for i in range(0x540 // 2, -1, -0xC0 // 2):
        if d: print('--------------------------- INVERSE ROUND: ', hex(i), hex(i<<1)) 

        t5 = inv_F(R5, key[i+0x90:i+0xA0], 0)
        if d: print('t5  :', dbg(t5))

        i0 = inv_SHF(t4, inv_unkn_220)
        i1 = inv_SHF(t5, inv_unkn_240)
        t1 = [a ^ b for a, b in zip(i0, i1)]    
        if d: print('t1  :', dbg(t1))

        i0 = inv_SHF(t6, inv_unkn_200)
        i1 = inv_F(R4, key[i+0xC0//2:i+0xC0//2 + 16])
        t0 = [a ^ b for a, b in zip(i0, i1)]    
        if d: print('t0  :', dbg(t0))
   
        # Forward job
        R2 = F(t0, key[i+0x40:i+0x50])
        if d: print('R2  :', dbg(R2))
    
        R2t1 = [(a + b) & 0xFFFF for a, b in zip(R2, t1)]

        t2 = S(R2t1)
        if d: print('t2  :', dbg(t2))

        R3 = F(t2, key[i+0x50:i+0x60])
        if d: print('R3  :', dbg(R3))

        # i1 = inv_F(R4) ~> xor with R3
        R0 = [a ^ b for a, b in zip(i1, R3)]    
        if d: print('R0  :', dbg(R0))

        p01 = inv_F(R0, key[i:i+0x10])
        if d: print('p01 :', dbg(p01))

        p45_key40 = [a ^ b for a, b in zip(t0, R0)]
        p45 = [(a - b) & 0xFFFF for a, b in zip(p45_key40, key[i+0x20:i+0x30])]
        if d: print('p45 :', dbg(p45))
    
        i2 = inv_SHF(t4, inv_unkn_220)
        R2R3 = [(a + b) & 0xFFFF for a, b in zip(R2, R3)] # q0
        i3 = [a ^ b for a, b in zip(i2, R2R3)]
        p23 = [(a - b) & 0xFFFF for a, b in zip(i3, key[i+0x10:i+0x20])]
        if d: print('p23 :', dbg(p23))

        R1q0 = inv_SHF(t5, inv_unkn_240)
        R1 = [a ^ b for a, b in zip(R2R3, R1q0)]
        if d: print('R1  :', dbg(R1))

        p67 = inv_F(R1, key[i+0x30:i+0x40])
        if d: print('p67 :', dbg(p67))

        R5 = R1
        R4 = R0 
        t6 = p23
        t4 = p45
#        break

    plaintext = p01[::-1] + p23[::-1] + p45[::-1] + p67[::-1]

    plaintext_bytes = []
    for p in plaintext:
        plaintext_bytes.append(p & 0xFF)
        plaintext_bytes.append(p >> 8)
    
    return plaintext_bytes


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Encryptor crack started.')

    print('[+] Testing sample encryption and decryption ...')
    # Sample encryption & decryption to prove correctness.
    ciphertext = u_encrypt(plain, key_debug, d=True)
    plaintext  = crack(ciphertext, key_debug, d=True)


    print('[+] Decrypting ciphertext file ...')

    cipher = open('ciphertext', 'rb').read()
    #cipher = open('/tmp/ciphertext', 'rb').read()

    print(f'[+] Ciphertext size: {len(cipher)}')

    open('ciphertext.cracked.progressive', 'wb').close()

    # Decrypt ciphertext block by block.
    plain = []
    for i in range(0, len(cipher)-128, 128):

        ciphertext = [
            (cipher[i+j+1] << 8) | cipher[i+j] for j in range(0, 128, 2)
        ]

        plaintext = crack(ciphertext, key_real, d=False)
        plain += plaintext

        print(f'[+] Decrypted plaintext at index {i}:', repr(bytes(plaintext[:16])))

        fp = open('ciphertext.cracked.progressive', 'ab')
        fp.write(bytes(plaintext))
        fp.close() 

        #break

    # Last block goes unencrypted.
    plain += cipher[i + 128:]
    
    print('[+] Last index:', i + 128)
    print('[+] Last block size:', len(cipher[i + 128:]))
    
    fp = open('ciphertext.cracked.progressive', 'ab')
    fp.write(bytes(cipher[i + 128:]))
    fp.close() 

    open('ciphertext.cracked.jpg', 'wb').write(bytes(plain))

    print('[+] Program finished. Bye bye :)')

# ----------------------------------------------------------------------------------------
r"""
[+] Encryptor crack started.
[+] Testing sample encryption and decryption ...
--------------------------- NEW ROUND:  0x0 0x0
p01 : 3842 3742 3642 3542 3442 3342 3242 3142 3841 3741 3641 3541 3441 3341 3241 3141
p23 : 3844 3744 3644 3544 3444 3344 3244 3144 3843 3743 3643 3543 3443 3343 3243 3143
p45 : 3846 3746 3646 3546 3446 3346 3246 3146 3845 3745 3645 3545 3445 3345 3245 3145
p67 : 3848 3748 3648 3548 3448 3348 3248 3148 3847 3747 3647 3547 3447 3347 3247 3147
R0  : 745D 220E 870B 28EE D60C 2FCE BC68 C55D 7D1E 096A E461 0C2C 729F D39D 9A33 F185
t0  : 8A6B 8F1D 7B2F 1BC5 2F59 2979 A463 D36C 8B14 0D70 906B 3E05 8095 A03E 3BF1 069F
R1  : 8438 7B9C 2CF3 76EC CBB9 75DA 7BBF FC33 0462 4792 C752 A995 C005 7AC9 2390 DC4C
t1  : A009 8738 B440 45E5 ED84 74D3 7606 D33A 167E 429A EB4A 8A9D C222 5BC1 B119 7C8C
R2  : B200 BDF4 4B3A DA3C A456 18D9 00ED 0FA0 9B60 6C2D E07C 8D13 B830 8A43 99F1 C232
t2  : 7E27 A318 4385 56C4 FF85 3D1F 083F 42FA 3E40 539A C2AB 6C1E 1A68 3767 F8D9 3C34
R3  : 5CB3 8FB0 AEDB CED7 F5A4 CAE9 2E64 40AB 2B77 266B 12A1 FFC0 B8F8 E8FC 7573 0A17
q0  : 0EB3 4DA4 FA15 A913 99FA E3C2 2F51 504B C6D7 9298 F31D 8CD3 7128 733F 0F64 CC49
t4  : 62A6 9A1A 2A82 B100 22E8 7F42 BFC7 E2CB DF05 AFDB D4CB 9790 9DED 6C89 730F 5237
t5  : 3638 D6E6 DFFF 8A8B 9618 54EE AC78 5243 D50A 344F 2546 C2B5 09F6 2CF4 1005 B12D
t6  : FDFC A285 22A3 52FF 569A 0CF1 CC5E 366F CDE9 DD7D 2271 66AB FD0D 4AF2 9B5F D4B1
R4  : 0850 A4CF 17B1 A2C0 BB3B F122 14E2 40C8 2D90 34BF 1EBA EEBB B377 F0AE C88A 4FA2
R5  : FD33 1628 7908 D4FD 4AE2 0546 BF18 AB83 D8B0 C49D 5755 BF15 E74D 9712 576C EA7B
--------------------------- NEW ROUND:  0x60 0xc0
p01 : 28EE ADBE 29D0 E639 23A8 E527 920C 85F6 5669 2F01 F6C0 F3EC CA67 3B61 EF40 FB92
p23 : FDFC A285 22A3 52FF 569A 0CF1 CC5E 366F CDE9 DD7D 2271 66AB FD0D 4AF2 9B5F D4B1
p45 : 62A6 9A1A 2A82 B100 22E8 7F42 BFC7 E2CB DF05 AFDB D4CB 9790 9DED 6C89 730F 5237
p67 : 3638 D6E6 DFFF 8A8B 9618 54EE AC78 5243 D50A 344F 2546 C2B5 09F6 2CF4 1005 B12D
R0  : 0850 A4CF 17B1 A2C0 BB3B F122 14E2 40C8 2D90 34BF 1EBA EEBB B377 F0AE C88A 4FA2
t0  : 8DD9 C1D5 5B00 807D 55D9 980E 5158 CAE6 F9E1 3BDF 18ED 5DC9 79BD 2D0C EE18 C5CB
R1  : FD33 1628 7908 D4FD 4AE2 0546 BF18 AB83 D8B0 C49D 5755 BF15 E74D 9712 576C EA7B
t1  : 2A9A 91D3 B1E1 5677 8D90 60B1 3DB9 4793 FD07 CACB 77B7 A541 3E8A AF2F EFD1 1A5D
R2  : B07C 7566 BFAC F2D7 C0F9 8047 DB11 BC5F 398B 7D4E 9E9C E34E AFC6 A752 1327 B685
t2  : 1B67 5BA6 7809 DC24 6136 097E 5DCA 80CB AAD2 5558 4A90 554D F9FF 4DC5 C0C1 1E30
R3  : 7504 15FE 8279 A024 156B E6DB 30CF 6817 667E A1F7 2284 3231 4AC2 773B 9BE9 02D2
q0  : 2580 8B64 4225 92FB D664 6722 0BE0 2476 A009 1F45 C120 157F FA88 1E8D AF10 B957
t4  : 8ACC 1071 F229 0C9F 8941 C866 1116 02D5 E1C2 0F2B 85BE 1113 17AD 4971 234F 26B0
t5  : 9D4C 3B2D 4606 D8B3 6264 B4F8 8FF5 9C86 DBD8 9675 AA6A 78B9 899F F87C 532C 1DC5
t6  : 8299 F08D 70E4 CEC8 E239 FB89 8FF7 7575 8143 B20F AE97 24D3 88BB 8008 AA99 BD7B
R4  : BA2A A004 8D40 661B A5B9 9B76 B292 5D1B F663 450F CA9E ACA1 A9C9 E731 2967 D47C
R5  : E605 EA2A 25FA 674B 3625 DB43 6FE8 F62A F2C0 0018 7EA2 14E2 832C 8025 270C 3148
--------------------------- NEW ROUND:  0xc0 0x180
p01 : 7D54 B131 95C8 02E4 AE50 17F9 242D 28DF 4BEE 9548 3C3E DC8A F9B5 8795 5363 4D70
p23 : 8299 F08D 70E4 CEC8 E239 FB89 8FF7 7575 8143 B20F AE97 24D3 88BB 8008 AA99 BD7B
p45 : 8ACC 1071 F229 0C9F 8941 C866 1116 02D5 E1C2 0F2B 85BE 1113 17AD 4971 234F 26B0
p67 : 9D4C 3B2D 4606 D8B3 6264 B4F8 8FF5 9C86 DBD8 9675 AA6A 78B9 899F F87C 532C 1DC5
R0  : BA2A A004 8D40 661B A5B9 9B76 B292 5D1B F663 450F CA9E ACA1 A9C9 E731 2967 D47C
t0  : 4949 CC09 2952 7FC7 83F8 430B 1D37 9060 2E66 48C6 7049 44DD E45B 1F91 5D46 7F9A
R1  : E605 EA2A 25FA 674B 3625 DB43 6FE8 F62A F2C0 0018 7EA2 14E2 832C 8025 270C 3148
t1  : AB1B B58A 8A94 4C3B 029F CCDD 426A 7571 B278 C89A B353 4E2F 8AB4 4E1D E736 D4C0
R2  : 38DD DA96 3EEA A568 7953 57CA 8022 4558 3628 FBC2 3659 40A5 2FA2 E467 ADFD 9824
t2  : 8C4B 3C95 30C7 CB1C DEB9 BD1D 29E7 6D53 6FCC D620 F9C8 0BA0 661A 5208 AB75 EE62
R3  : B155 9250 1ACE 1B90 C4A4 1CAF B97E 04E1 2194 95DE 4C5F 9E8F FFD8 72CE C783 100B
q0  : EA32 6CE6 59B8 C0F8 3DF7 7479 39A0 4A39 57BC 91A0 82B8 DF34 2F7A 5735 7580 A82F
t4  : F6D6 EB88 A72C 3346 1422 C962 094D 63E7 4F49 85F9 1704 5922 B5BA 4DA7 26E2 990D
t5  : 86CC 7C42 A7B3 0C37 AF3A 5648 BC13 0BD2 91B8 FC1A CBD6 A57C D710 528C 9967 AC56
t6  : 024C 4236 FE5D BEDC C99A E2E5 C4D2 16DB 76F3 F991 9817 F688 BBED B24A 8A6E B3A2
R4  : 6D56 ACC1 111F A654 6A76 06B1 765E F02D 88C6 F776 842A E2FF D8A8 F1C5 B6C6 AACF
R5  : 11B6 81ED 934A 9485 2121 35A3 E0DE 9E2D 8709 0841 78AE 1D1B 5697 81C5 1B8F 0D8C
--------------------------- NEW ROUND:  0x120 0x240
p01 : 0B7F 3254 978E 7D8B 611D 87D9 0BEC 59FA D7F7 D0D1 86C1 322E 5611 95FF EEE4 C477
p23 : 024C 4236 FE5D BEDC C99A E2E5 C4D2 16DB 76F3 F991 9817 F688 BBED B24A 8A6E B3A2
p45 : F6D6 EB88 A72C 3346 1422 C962 094D 63E7 4F49 85F9 1704 5922 B5BA 4DA7 26E2 990D
p67 : 86CC 7C42 A7B3 0C37 AF3A 5648 BC13 0BD2 91B8 FC1A CBD6 A57C D710 528C 9967 AC56
R0  : 6D56 ACC1 111F A654 6A76 06B1 765E F02D 88C6 F776 842A E2FF D8A8 F1C5 B6C6 AACF
t0  : AAD6 C417 45C2 970C 75D1 2270 15CE E564 315C 5DF2 0A34 8A2E 7904 18D3 CBB5 6155
R1  : 11B6 81ED 934A 9485 2121 35A3 E0DE 9E2D 8709 0841 78AE 1D1B 5697 81C5 1B8F 0D8C
t1  : 802C 20D8 D789 538B 4E9F C2C6 BB7C 005E B784 40FD 8FD6 AF2E 86EC 625F 6C11 DAA1
R2  : C18B CBD2 1982 80D5 E3D8 0A25 46B3 0CD3 878E 86F5 5936 980E 1D95 15E2 8A51 3E87
t2  : E242 3ECB 423F 16C0 BD79 C07C 6E08 E28F 999E 60CF E220 4DA1 EC74 F266 D983 F41B
R3  : 63AE 4255 FEFB C434 224D F254 3CA0 7501 30C7 99FB FF7E 025C FDDC 4DE8 A34B C6A4
q0  : 2539 0E27 187D 4509 0625 FC79 8353 81D4 B855 20F0 58B4 9A6A 1B71 63CA 2D9C 052B
t4  : 5CBE 8207 B4A3 AF12 D8F1 1FA7 699B 0B1C AFCC 285F 88D8 684C 5A02 D206 CB0A 8050
t5  : 8FCA 8B37 D18C 348F C9DA 638D 1FF9 2704 28B1 201A 8771 3F5C E20F 3613 08A7 4DE6
t6  : F56C A42E 2A83 AA26 6048 3DEA D695 5F30 6A8D 895D 337F 7160 0D3E 5C70 A4FE DE38
R4  : 10B2 C074 5ECF 3FB2 C9A0 2D5A 90E5 0C47 342D B43C 3C50 D102 0BC3 658B E867 EC37
R5  : 7630 07CE 7819 E0AD 8BD4 6BDC AC7C 10F4 3758 1204 0365 36D6 1A48 32B9 8CFA D790
--------------------------- NEW ROUND:  0x180 0x300
p01 : 0EF8 EE94 EFE4 6260 483B F4E5 4AFE 852C B801 6E8D 7B54 E0A3 2574 BC2D 158D 6C6B
p23 : F56C A42E 2A83 AA26 6048 3DEA D695 5F30 6A8D 895D 337F 7160 0D3E 5C70 A4FE DE38
p45 : 5CBE 8207 B4A3 AF12 D8F1 1FA7 699B 0B1C AFCC 285F 88D8 684C 5A02 D206 CB0A 8050
p67 : 8FCA 8B37 D18C 348F C9DA 638D 1FF9 2704 28B1 201A 8771 3F5C E20F 3613 08A7 4DE6
R0  : 10B2 C074 5ECF 3FB2 C9A0 2D5A 90E5 0C47 342D B43C 3C50 D102 0BC3 658B E867 EC37
t0  : 3CA7 97E7 084E 1441 688E 8A4F 9C8F 3F46 7DBE 26D0 6B01 42D6 7CD2 B558 AD6E 5B15
R1  : 7630 07CE 7819 E0AD 8BD4 6BDC AC7C 10F4 3758 1204 0365 36D6 1A48 32B9 8CFA D790
t1  : 060D 113C EC4C 3EA9 5612 CAE5 B037 32F3 59D5 9DC3 648F EB54 B0F2 49BA 0620 FB67
R2  : 9B93 B90B B6B2 C675 B228 D396 43CD 4423 F3FE A75A 0F98 2B7C A2BA 44AD 8B0F 1E1C
t2  : 24F6 D18E BF8B 86F4 E331 A787 35A9 644C 91EC 3EB8 7C6A B907 9295 60BB FAD8 5D91
R3  : 4384 11BE B8F2 9C44 8061 BC3B DB15 7334 396A A445 CA91 FF30 BFEC 0FA3 38CC A4CD
q0  : DF17 CAC9 6FA4 62B9 3289 8FD1 1EE2 B757 2D68 4B9F DA29 2AAC 62A6 5450 C3DB C2E9
t4  : FBF1 BCBD AF2A DC3B 02A9 9550 EF4F 2EE8 BDC3 F72E 43E5 C458 4901 EE1E C81C 2F53
t5  : CD07 17BD 8214 A927 E40D B29E A7A3 B95D 599B D94C 1C7A 1A30 66E9 4F21 1579 78EE
t6  : B7B7 6F91 462D EE73 4035 214F 1B2E D77F 6CE4 70F9 36A9 9DC0 13EF C8FD DF70 7DC5
R4  : 21A6 D11C 2CA3 55FB 2821 C4E9 DC5B FE6A 42BF 6AC3 11BC 3B28 1822 2ED8 145A C7F2
R5  : E377 5CE9 5172 3BED A238 E245 A536 5828 DA1B 2B38 48CB 32BB F563 88AF F8CE DCC6
--------------------------- NEW ROUND:  0x1e0 0x3c0
p01 : 5336 D1CA E63D A3F6 49C1 9161 4BF0 7F73 0D47 1079 F6C1 2E32 B42F 6A28 D0AB 48FA
p23 : B7B7 6F91 462D EE73 4035 214F 1B2E D77F 6CE4 70F9 36A9 9DC0 13EF C8FD DF70 7DC5
p45 : FBF1 BCBD AF2A DC3B 02A9 9550 EF4F 2EE8 BDC3 F72E 43E5 C458 4901 EE1E C81C 2F53
p67 : CD07 17BD 8214 A927 E40D B29E A7A3 B95D 599B D94C 1C7A 1A30 66E9 4F21 1579 78EE
R0  : 21A6 D11C 2CA3 55FB 2821 C4E9 DC5B FE6A 42BF 6AC3 11BC 3B28 1822 2ED8 145A C7F2
t0  : DC0D 31D0 F614 FC09 42EB 63F0 A2B8 C868 D993 458B FA32 2633 AA94 37C4 7CEE 5E61
R1  : E377 5CE9 5172 3BED A238 E245 A536 5828 DA1B 2B38 48CB 32BB F563 88AF F8CE DCC6
t1  : EAE9 B792 562B E4D8 7DBD 52E6 9407 9FEB B3D3 701E 5CCD C0DC C3F6 92D6 E898 ACCB
R2  : D048 07B3 CB1E 65B1 BB51 662F A9B3 A3FF 4901 C4E0 4D51 DDAE 7190 7B68 D3A3 2FDB
t2  : 37D8 D819 72C8 F2BD 328D 4745 CA82 4101 C4D6 5839 6B4D 0B1C BCCE 226B 8339 46B9
R3  : 87A7 3E0D C29A 95A0 0788 2B7D 7B31 49EE 5FA1 A198 B87A 12F3 9028 8DD7 D2FE 93A9
q0  : 57EF 45C0 8DB8 FB51 C2D9 91AC 24E4 EDED A8A2 6678 05CB F0A1 01B8 093F A6A1 C384
t4  : 8AE1 2464 5E71 AEBB 15D5 2A2E 1D5C 210F 11CD 02C6 C16A 3D5E B6F7 B389 372D 1346
t5  : 1929 DCCA C0BC B498 73E9 81D2 B5C5 60E1 4D40 4D00 C21A 72B9 8190 5E6F 1F42 F4DB
t6  : 3C52 7A0C DEC1 182D 7FEC 6D42 8C64 05D2 0FE8 C48D 8ED0 53F4 0A3A 229E 94CB BA4A
R4  : EDE8 FE2E E662 822B 17BF 0E53 9379 7153 96B7 104A 4206 18D0 D8EA CD74 57D8 9B95
R5  : 087B 5751 505E 90BF 2572 5314 F6E6 16F9 38AE 559C 0985 3B4D CC34 1105 443D 944A
--------------------------- NEW ROUND:  0x240 0x480
p01 : A601 EF11 EE39 C05B 2FA9 EF94 A76A B784 1D1E CB5B A9C6 29DB 880A A30F C6A4 545B
p23 : 3C52 7A0C DEC1 182D 7FEC 6D42 8C64 05D2 0FE8 C48D 8ED0 53F4 0A3A 229E 94CB BA4A
p45 : 8AE1 2464 5E71 AEBB 15D5 2A2E 1D5C 210F 11CD 02C6 C16A 3D5E B6F7 B389 372D 1346
p67 : 1929 DCCA C0BC B498 73E9 81D2 B5C5 60E1 4D40 4D00 C21A 72B9 8190 5E6F 1F42 F4DB
R0  : EDE8 FE2E E662 822B 17BF 0E53 9379 7153 96B7 104A 4206 18D0 D8EA CD74 57D8 9B95
t0  : 1A83 D7F4 ED43 7A2C C840 9045 7FB1 7A90 4FEB 46A0 A727 F00F 8561 46CC E663 5738
R1  : 087B 5751 505E 90BF 2572 5314 F6E6 16F9 38AE 559C 0985 3B4D CC34 1105 443D 944A
t1  : 5136 CEFC 6920 812B 827B 0B63 F3A8 09D3 0CF9 8E90 4513 DF40 7627 5171 C0D3 7E71
R2  : F904 3B72 D4BC 66F8 4E10 A999 AAF0 F11B AA9C CDF9 F88B 6C4A F001 07FE 3AA4 CF57
t2  : 9B8E 1F6D C713 D65B 8440 7C13 CA51 3203 D28E 1794 62B8 3AAA B810 AE19 3692 A963
R3  : EF8F A7DB 3CED 160C A754 FF91 2BEE 0E2F FCA0 876B AA45 D2CF DDA6 5264 8A5F AAC6
q0  : E893 E34D 11A9 7D04 F564 A92A D6DE FF4A A73C 5564 A2D0 3F19 CDA7 5A62 C503 7A1D
t4  : 28D7 6C90 B1DE 7AE0 D390 E060 526D F15D EE46 DB14 936B 8E68 41ED 9026 77B4 1A16
t5  : B41C 41F7 EDBB E0E8 FA3E 2038 E9B3 D016 00F8 AB55 0454 9F92 4B67 813E EE57 0193
t6  : EE0B 18E4 8E01 37CC 05EC 78AB 6187 C726 3A10 25FC D181 4F64 666B 802D D9DC 3BE4
R4  : 19ED DB73 9E41 25F8 D87F 1D00 8509 76D0 61AB 08F1 8665 AED6 B3A2 349F 7C0C 4C9F
R5  : 3956 28A1 B3CC BB9D AD0B 857F A889 BED2 6B77 CCAA B170 4036 F78E F63B 05DB 0348
--------------------------- NEW ROUND:  0x2a0 0x540
p01 : 0267 59F5 DA8F 9427 B0EB F1C2 B897 7F7C 6A17 9721 E843 CA1F 054C 9F10 DD87 3153
p23 : EE0B 18E4 8E01 37CC 05EC 78AB 6187 C726 3A10 25FC D181 4F64 666B 802D D9DC 3BE4
p45 : 28D7 6C90 B1DE 7AE0 D390 E060 526D F15D EE46 DB14 936B 8E68 41ED 9026 77B4 1A16
p67 : B41C 41F7 EDBB E0E8 FA3E 2038 E9B3 D016 00F8 AB55 0454 9F92 4B67 813E EE57 0193
R0  : 19ED DB73 9E41 25F8 D87F 1D00 8509 76D0 61AB 08F1 8665 AED6 B3A2 349F 7C0C 4C9F
t0  : C1D3 6E69 15C1 995A 7993 BFB5 544C F9BD 0E37 4B41 3A14 BDE6 3641 AB25 FB0C 2CC7
R1  : 3956 28A1 B3CC BB9D AD0B 857F A889 BED2 6B77 CCAA B170 4036 F78E F63B 05DB 0348
t1  : F945 6171 C86D 6B18 E783 F540 E46C 5241 3F2A 94AF 6640 16DD 5F75 DECF 1921 7536
R2  : 5302 0C69 341C 62C4 A273 E876 CB02 90A9 83E9 7308 18DD 206C 07F5 E936 8BB2 8140
t2  : 5F94 3E28 CECA BFBE 460A 6CF2 531A 6026 A77A 0222 02B9 2B11 B8B5 6B3C 80B5 AEF6
R3  : B8BE D029 E137 D41A DAD7 6652 DE49 41F9 B281 2D65 753E 7F7C 2C70 B302 DD33 14AD
q0  : 0BC0 DC92 1553 36DE 7D4A 4EC8 A94B D2A2 366A A06D 8E1B 9FE8 3465 9C38 68E5 95ED
t4  : 6EF2 E65B CBD3 9542 E5AE 3E31 37C2 3EF7 592B C903 6237 F868 741F E393 9C9E B4CC
t5  : F433 A69F 8D43 3296 CBB7 01C2 6C70 D041 6CC7 3F6B DFDE 5D1D 6A03 6D3E 96A5 C3EB
t6  : 68B8 6080 6533 6AB7 CE94 7B3B C4E7 0F0C 6C4C DD1D 6ED5 C94F 74F5 A993 2CB8 5A33
R4  : 8765 05DE 7709 0927 B6FE 3224 9EB7 8FC0 DFAB 6D45 0755 1FD1 0EF7 41F9 7036 6BE8
R5  : 5B7B 776A 5A7F A0E6 C016 007D 0395 1995 D811 54FB 8081 5C21 9A80 7734 653C 555B
Ciphertext: 8765 05DE 7709 0927 B6FE 3224 9EB7 8FC0 DFAB 6D45 0755 1FD1 0EF7 41F9 7036 6BE8 D549 2544 43E7 2034 5A92 0470 9E45 007C C5CB 66AD 730F B3CA AD84 4AB3 231E 498E 57DB B005 3229 28FE 944F D815 4543 DA0B 8EEB 8847 6CD5 F89F DFFC A0CE F859 6203 5B7B 776A 5A7F A0E6 C016 007D 0395 1995 D811 54FB 8081 5C21 9A80 7734 653C 555B
ciphertexts match!!
~ = ~ = ~ = CRACK = ~ = ~ = ~
R5:  5B7B 776A 5A7F A0E6 C016 007D 0395 1995 D811 54FB 8081 5C21 9A80 7734 653C 555B
R4:  8765 05DE 7709 0927 B6FE 3224 9EB7 8FC0 DFAB 6D45 0755 1FD1 0EF7 41F9 7036 6BE8
t6:  68B8 6080 6533 6AB7 CE94 7B3B C4E7 0F0C 6C4C DD1D 6ED5 C94F 74F5 A993 2CB8 5A33
t4:  6EF2 E65B CBD3 9542 E5AE 3E31 37C2 3EF7 592B C903 6237 F868 741F E393 9C9E B4CC
--------------------------- INVERSE ROUND:  0x2a0 0x540
t5  : F433 A69F 8D43 3296 CBB7 01C2 6C70 D041 6CC7 3F6B DFDE 5D1D 6A03 6D3E 96A5 C3EB
t1  : F945 6171 C86D 6B18 E783 F540 E46C 5241 3F2A 94AF 6640 16DD 5F75 DECF 1921 7536
t0  : C1D3 6E69 15C1 995A 7993 BFB5 544C F9BD 0E37 4B41 3A14 BDE6 3641 AB25 FB0C 2CC7
R2  : 5302 0C69 341C 62C4 A273 E876 CB02 90A9 83E9 7308 18DD 206C 07F5 E936 8BB2 8140
t2  : 5F94 3E28 CECA BFBE 460A 6CF2 531A 6026 A77A 0222 02B9 2B11 B8B5 6B3C 80B5 AEF6
R3  : B8BE D029 E137 D41A DAD7 6652 DE49 41F9 B281 2D65 753E 7F7C 2C70 B302 DD33 14AD
R0  : 19ED DB73 9E41 25F8 D87F 1D00 8509 76D0 61AB 08F1 8665 AED6 B3A2 349F 7C0C 4C9F
p01 : 0267 59F5 DA8F 9427 B0EB F1C2 B897 7F7C 6A17 9721 E843 CA1F 054C 9F10 DD87 3153
p45 : 28D7 6C90 B1DE 7AE0 D390 E060 526D F15D EE46 DB14 936B 8E68 41ED 9026 77B4 1A16
p23 : EE0B 18E4 8E01 37CC 05EC 78AB 6187 C726 3A10 25FC D181 4F64 666B 802D D9DC 3BE4
R1  : 3956 28A1 B3CC BB9D AD0B 857F A889 BED2 6B77 CCAA B170 4036 F78E F63B 05DB 0348
p67 : B41C 41F7 EDBB E0E8 FA3E 2038 E9B3 D016 00F8 AB55 0454 9F92 4B67 813E EE57 0193
--------------------------- INVERSE ROUND:  0x240 0x480
t5  : B41C 41F7 EDBB E0E8 FA3E 2038 E9B3 D016 00F8 AB55 0454 9F92 4B67 813E EE57 0193
t1  : 5136 CEFC 6920 812B 827B 0B63 F3A8 09D3 0CF9 8E90 4513 DF40 7627 5171 C0D3 7E71
t0  : 1A83 D7F4 ED43 7A2C C840 9045 7FB1 7A90 4FEB 46A0 A727 F00F 8561 46CC E663 5738
R2  : F904 3B72 D4BC 66F8 4E10 A999 AAF0 F11B AA9C CDF9 F88B 6C4A F001 07FE 3AA4 CF57
t2  : 9B8E 1F6D C713 D65B 8440 7C13 CA51 3203 D28E 1794 62B8 3AAA B810 AE19 3692 A963
R3  : EF8F A7DB 3CED 160C A754 FF91 2BEE 0E2F FCA0 876B AA45 D2CF DDA6 5264 8A5F AAC6
R0  : EDE8 FE2E E662 822B 17BF 0E53 9379 7153 96B7 104A 4206 18D0 D8EA CD74 57D8 9B95
p01 : A601 EF11 EE39 C05B 2FA9 EF94 A76A B784 1D1E CB5B A9C6 29DB 880A A30F C6A4 545B
p45 : 8AE1 2464 5E71 AEBB 15D5 2A2E 1D5C 210F 11CD 02C6 C16A 3D5E B6F7 B389 372D 1346
p23 : 3C52 7A0C DEC1 182D 7FEC 6D42 8C64 05D2 0FE8 C48D 8ED0 53F4 0A3A 229E 94CB BA4A
R1  : 087B 5751 505E 90BF 2572 5314 F6E6 16F9 38AE 559C 0985 3B4D CC34 1105 443D 944A
p67 : 1929 DCCA C0BC B498 73E9 81D2 B5C5 60E1 4D40 4D00 C21A 72B9 8190 5E6F 1F42 F4DB
--------------------------- INVERSE ROUND:  0x1e0 0x3c0
t5  : 1929 DCCA C0BC B498 73E9 81D2 B5C5 60E1 4D40 4D00 C21A 72B9 8190 5E6F 1F42 F4DB
t1  : EAE9 B792 562B E4D8 7DBD 52E6 9407 9FEB B3D3 701E 5CCD C0DC C3F6 92D6 E898 ACCB
t0  : DC0D 31D0 F614 FC09 42EB 63F0 A2B8 C868 D993 458B FA32 2633 AA94 37C4 7CEE 5E61
R2  : D048 07B3 CB1E 65B1 BB51 662F A9B3 A3FF 4901 C4E0 4D51 DDAE 7190 7B68 D3A3 2FDB
t2  : 37D8 D819 72C8 F2BD 328D 4745 CA82 4101 C4D6 5839 6B4D 0B1C BCCE 226B 8339 46B9
R3  : 87A7 3E0D C29A 95A0 0788 2B7D 7B31 49EE 5FA1 A198 B87A 12F3 9028 8DD7 D2FE 93A9
R0  : 21A6 D11C 2CA3 55FB 2821 C4E9 DC5B FE6A 42BF 6AC3 11BC 3B28 1822 2ED8 145A C7F2
p01 : 5336 D1CA E63D A3F6 49C1 9161 4BF0 7F73 0D47 1079 F6C1 2E32 B42F 6A28 D0AB 48FA
p45 : FBF1 BCBD AF2A DC3B 02A9 9550 EF4F 2EE8 BDC3 F72E 43E5 C458 4901 EE1E C81C 2F53
p23 : B7B7 6F91 462D EE73 4035 214F 1B2E D77F 6CE4 70F9 36A9 9DC0 13EF C8FD DF70 7DC5
R1  : E377 5CE9 5172 3BED A238 E245 A536 5828 DA1B 2B38 48CB 32BB F563 88AF F8CE DCC6
p67 : CD07 17BD 8214 A927 E40D B29E A7A3 B95D 599B D94C 1C7A 1A30 66E9 4F21 1579 78EE
--------------------------- INVERSE ROUND:  0x180 0x300
t5  : CD07 17BD 8214 A927 E40D B29E A7A3 B95D 599B D94C 1C7A 1A30 66E9 4F21 1579 78EE
t1  : 060D 113C EC4C 3EA9 5612 CAE5 B037 32F3 59D5 9DC3 648F EB54 B0F2 49BA 0620 FB67
t0  : 3CA7 97E7 084E 1441 688E 8A4F 9C8F 3F46 7DBE 26D0 6B01 42D6 7CD2 B558 AD6E 5B15
R2  : 9B93 B90B B6B2 C675 B228 D396 43CD 4423 F3FE A75A 0F98 2B7C A2BA 44AD 8B0F 1E1C
t2  : 24F6 D18E BF8B 86F4 E331 A787 35A9 644C 91EC 3EB8 7C6A B907 9295 60BB FAD8 5D91
R3  : 4384 11BE B8F2 9C44 8061 BC3B DB15 7334 396A A445 CA91 FF30 BFEC 0FA3 38CC A4CD
R0  : 10B2 C074 5ECF 3FB2 C9A0 2D5A 90E5 0C47 342D B43C 3C50 D102 0BC3 658B E867 EC37
p01 : 0EF8 EE94 EFE4 6260 483B F4E5 4AFE 852C B801 6E8D 7B54 E0A3 2574 BC2D 158D 6C6B
p45 : 5CBE 8207 B4A3 AF12 D8F1 1FA7 699B 0B1C AFCC 285F 88D8 684C 5A02 D206 CB0A 8050
p23 : F56C A42E 2A83 AA26 6048 3DEA D695 5F30 6A8D 895D 337F 7160 0D3E 5C70 A4FE DE38
R1  : 7630 07CE 7819 E0AD 8BD4 6BDC AC7C 10F4 3758 1204 0365 36D6 1A48 32B9 8CFA D790
p67 : 8FCA 8B37 D18C 348F C9DA 638D 1FF9 2704 28B1 201A 8771 3F5C E20F 3613 08A7 4DE6
--------------------------- INVERSE ROUND:  0x120 0x240
t5  : 8FCA 8B37 D18C 348F C9DA 638D 1FF9 2704 28B1 201A 8771 3F5C E20F 3613 08A7 4DE6
t1  : 802C 20D8 D789 538B 4E9F C2C6 BB7C 005E B784 40FD 8FD6 AF2E 86EC 625F 6C11 DAA1
t0  : AAD6 C417 45C2 970C 75D1 2270 15CE E564 315C 5DF2 0A34 8A2E 7904 18D3 CBB5 6155
R2  : C18B CBD2 1982 80D5 E3D8 0A25 46B3 0CD3 878E 86F5 5936 980E 1D95 15E2 8A51 3E87
t2  : E242 3ECB 423F 16C0 BD79 C07C 6E08 E28F 999E 60CF E220 4DA1 EC74 F266 D983 F41B
R3  : 63AE 4255 FEFB C434 224D F254 3CA0 7501 30C7 99FB FF7E 025C FDDC 4DE8 A34B C6A4
R0  : 6D56 ACC1 111F A654 6A76 06B1 765E F02D 88C6 F776 842A E2FF D8A8 F1C5 B6C6 AACF
p01 : 0B7F 3254 978E 7D8B 611D 87D9 0BEC 59FA D7F7 D0D1 86C1 322E 5611 95FF EEE4 C477
p45 : F6D6 EB88 A72C 3346 1422 C962 094D 63E7 4F49 85F9 1704 5922 B5BA 4DA7 26E2 990D
p23 : 024C 4236 FE5D BEDC C99A E2E5 C4D2 16DB 76F3 F991 9817 F688 BBED B24A 8A6E B3A2
R1  : 11B6 81ED 934A 9485 2121 35A3 E0DE 9E2D 8709 0841 78AE 1D1B 5697 81C5 1B8F 0D8C
p67 : 86CC 7C42 A7B3 0C37 AF3A 5648 BC13 0BD2 91B8 FC1A CBD6 A57C D710 528C 9967 AC56
--------------------------- INVERSE ROUND:  0xc0 0x180
t5  : 86CC 7C42 A7B3 0C37 AF3A 5648 BC13 0BD2 91B8 FC1A CBD6 A57C D710 528C 9967 AC56
t1  : AB1B B58A 8A94 4C3B 029F CCDD 426A 7571 B278 C89A B353 4E2F 8AB4 4E1D E736 D4C0
t0  : 4949 CC09 2952 7FC7 83F8 430B 1D37 9060 2E66 48C6 7049 44DD E45B 1F91 5D46 7F9A
R2  : 38DD DA96 3EEA A568 7953 57CA 8022 4558 3628 FBC2 3659 40A5 2FA2 E467 ADFD 9824
t2  : 8C4B 3C95 30C7 CB1C DEB9 BD1D 29E7 6D53 6FCC D620 F9C8 0BA0 661A 5208 AB75 EE62
R3  : B155 9250 1ACE 1B90 C4A4 1CAF B97E 04E1 2194 95DE 4C5F 9E8F FFD8 72CE C783 100B
R0  : BA2A A004 8D40 661B A5B9 9B76 B292 5D1B F663 450F CA9E ACA1 A9C9 E731 2967 D47C
p01 : 7D54 B131 95C8 02E4 AE50 17F9 242D 28DF 4BEE 9548 3C3E DC8A F9B5 8795 5363 4D70
p45 : 8ACC 1071 F229 0C9F 8941 C866 1116 02D5 E1C2 0F2B 85BE 1113 17AD 4971 234F 26B0
p23 : 8299 F08D 70E4 CEC8 E239 FB89 8FF7 7575 8143 B20F AE97 24D3 88BB 8008 AA99 BD7B
R1  : E605 EA2A 25FA 674B 3625 DB43 6FE8 F62A F2C0 0018 7EA2 14E2 832C 8025 270C 3148
p67 : 9D4C 3B2D 4606 D8B3 6264 B4F8 8FF5 9C86 DBD8 9675 AA6A 78B9 899F F87C 532C 1DC5
--------------------------- INVERSE ROUND:  0x60 0xc0
t5  : 9D4C 3B2D 4606 D8B3 6264 B4F8 8FF5 9C86 DBD8 9675 AA6A 78B9 899F F87C 532C 1DC5
t1  : 2A9A 91D3 B1E1 5677 8D90 60B1 3DB9 4793 FD07 CACB 77B7 A541 3E8A AF2F EFD1 1A5D
t0  : 8DD9 C1D5 5B00 807D 55D9 980E 5158 CAE6 F9E1 3BDF 18ED 5DC9 79BD 2D0C EE18 C5CB
R2  : B07C 7566 BFAC F2D7 C0F9 8047 DB11 BC5F 398B 7D4E 9E9C E34E AFC6 A752 1327 B685
t2  : 1B67 5BA6 7809 DC24 6136 097E 5DCA 80CB AAD2 5558 4A90 554D F9FF 4DC5 C0C1 1E30
R3  : 7504 15FE 8279 A024 156B E6DB 30CF 6817 667E A1F7 2284 3231 4AC2 773B 9BE9 02D2
R0  : 0850 A4CF 17B1 A2C0 BB3B F122 14E2 40C8 2D90 34BF 1EBA EEBB B377 F0AE C88A 4FA2
p01 : 28EE ADBE 29D0 E639 23A8 E527 920C 85F6 5669 2F01 F6C0 F3EC CA67 3B61 EF40 FB92
p45 : 62A6 9A1A 2A82 B100 22E8 7F42 BFC7 E2CB DF05 AFDB D4CB 9790 9DED 6C89 730F 5237
p23 : FDFC A285 22A3 52FF 569A 0CF1 CC5E 366F CDE9 DD7D 2271 66AB FD0D 4AF2 9B5F D4B1
R1  : FD33 1628 7908 D4FD 4AE2 0546 BF18 AB83 D8B0 C49D 5755 BF15 E74D 9712 576C EA7B
p67 : 3638 D6E6 DFFF 8A8B 9618 54EE AC78 5243 D50A 344F 2546 C2B5 09F6 2CF4 1005 B12D
--------------------------- INVERSE ROUND:  0x0 0x0
t5  : 3638 D6E6 DFFF 8A8B 9618 54EE AC78 5243 D50A 344F 2546 C2B5 09F6 2CF4 1005 B12D
t1  : A009 8738 B440 45E5 ED84 74D3 7606 D33A 167E 429A EB4A 8A9D C222 5BC1 B119 7C8C
t0  : 8A6B 8F1D 7B2F 1BC5 2F59 2979 A463 D36C 8B14 0D70 906B 3E05 8095 A03E 3BF1 069F
R2  : B200 BDF4 4B3A DA3C A456 18D9 00ED 0FA0 9B60 6C2D E07C 8D13 B830 8A43 99F1 C232
t2  : 7E27 A318 4385 56C4 FF85 3D1F 083F 42FA 3E40 539A C2AB 6C1E 1A68 3767 F8D9 3C34
R3  : 5CB3 8FB0 AEDB CED7 F5A4 CAE9 2E64 40AB 2B77 266B 12A1 FFC0 B8F8 E8FC 7573 0A17
R0  : 745D 220E 870B 28EE D60C 2FCE BC68 C55D 7D1E 096A E461 0C2C 729F D39D 9A33 F185
p01 : 3842 3742 3642 3542 3442 3342 3242 3142 3841 3741 3641 3541 3441 3341 3241 3141
p45 : 3846 3746 3646 3546 3446 3346 3246 3146 3845 3745 3645 3545 3445 3345 3245 3145
p23 : 3844 3744 3644 3544 3444 3344 3244 3144 3843 3743 3643 3543 3443 3343 3243 3143
R1  : 8438 7B9C 2CF3 76EC CBB9 75DA 7BBF FC33 0462 4792 C752 A995 C005 7AC9 2390 DC4C
p67 : 3848 3748 3648 3548 3448 3348 3248 3148 3847 3747 3647 3547 3447 3347 3247 3147
[+] Decrypting ciphertext file ...
[+] Ciphertext size: 422208
[+] Decrypted plaintext at index 0: b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00H'
[+] Decrypted plaintext at index 128: b'8BIM\x04\x04\x00\x00\x00\x00\x00\x008BIM'
[+] Decrypted plaintext at index 256: b'Q2\x14aq#\x07\x81 \x91B\x15\xa1R3\xb1'
[+] Decrypted plaintext at index 384: b'\xba\xc0\xc4\xc5\xc6\xc7\xc8\xc9\xca\xd0\xd4\xd5\xd6\xd7\xd8\xd9'
[+] Decrypted plaintext at index 512: b'\xf0\xd1%`\xc1D\xe1r\xf1\x17\x82c6p&E'
[+] Decrypted plaintext at index 640: b'\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xff\xdb\x00C\x00\x06\x04\x05\x06'
[+] Decrypted plaintext at index 768: b'(((((((((((((((('
[+] Decrypted plaintext at index 896: b'\x1b,7\xb2\xa6*\xed\xb5\x16\xa3\xa3\x17\xf5\xd3:\x03'
[+] Decrypted plaintext at index 1024: b'Y\x14\xeb\xb93Y3\x05\xba\x03=\xc8\xce\x86\xb0\x0c'
[+] Decrypted plaintext at index 1152: b'\x9d\xa7\x1c\x88\x9d\x847\xe8n\x8b\x93\xec\xf3}\x16\xaf'
[+] Decrypted plaintext at index 1280: b'X\x11Ui\xddNnf\x80=\n\x93)\xe1\xc3\x05'
[+] Decrypted plaintext at index 1408: b'S\xb1\xfd{R\xdf\\\xfa@t`\xeb\x1c\xc2\x85s'
[+] Decrypted plaintext at index 1536: b'/g\xce\x15\xee9\xaa\xea\xeb\xe9\xf3\x02\\\xb1S\\'
[+] Decrypted plaintext at index 1664: b'\x90cB\x06@\xe1\xa7\x90\x8c\xed\x08\xccW\xaa$4'
[+] Decrypted plaintext at index 1792: b'\xaf?v\xcb\xaf\xc9\xb4l\xd9\x82\xc2<\x93\x8c\xf6\xe7'
[+] Decrypted plaintext at index 1920: b'\x9dZ\x1d\xd75R\xe5\x14\x17\x14\xcd\x1a\xa3\xe1+C'
[+] Decrypted plaintext at index 2048: b'{c\xce\xd6ca\\\xbb\x90\xce\xdd\xba9Kf\xd6'
[+] Decrypted plaintext at index 2176: b'\x0e\x1d\x1a\x19Y\x927\xc5f\xeb\xe5y\x99@\xcb\x1d'
[+] Decrypted plaintext at index 2304: b'\xb1\x10\xf1]6Z\xf0\x9d\x125\x13|\x9b\xa3\xe4\xb4'
[+] Decrypted plaintext at index 2432: b']\xd8\x9ej\xb2\xf2\xee\xcdY\xbbBtfm\x8e\xe3'
[+] Decrypted plaintext at index 2560: b'7}9U\x1f\\\xc2\xf0\x16\xae\x83%JZ-\x84'
[+] Decrypted plaintext at index 2688: b'\xdeI\t`\xa1\xc4G`\xc6\xc4\xde\xa9N\x9e\x8d\xb5'
[+] Decrypted plaintext at index 2816: b'\x8a\x82\xc5f-\xb1\xdc;\x9fw\xac@z\xc77\xb1'
[+] Decrypted plaintext at index 2944: b'`a\xadH<\xfe\xe4\xc1V\xa0lmG\xb2u\x95'
[+] Decrypted plaintext at index 3072: b'>^\xd7#\xe6e\xa5L\xa9\xc1v\xe8\x01\xa6\xa5u'
[+] Decrypted plaintext at index 3200: b'\x0b^\x8c\xdc\xb3|\xf1M\x82\xca\x19\xe8\xcdH\xa56'
[+] Decrypted plaintext at index 3328: b'\x84i\x11\xd4\xa9K\xcf\x1bf\xd6-s\xbd\x80\xbd\xda'
[+] Decrypted plaintext at index 3456: b'\x8a|\xf5%o\x1fZ\xc7\xa6FZ\x92\x83-H\xdd'
[+] Decrypted plaintext at index 3584: b"\xeb\xe6z\xc4\xcfF\xca\xd9\x18tV\xcf'Es\xb0"
[+] Decrypted plaintext at index 3712: b'\xaf=\x8c\xfb>\xc6\xd1\x0b)\xe6\xd5j\xc8L`\x15'
[+] Decrypted plaintext at index 3840: b'\xe8A\x8d\xf2n\xb0\xb0\xe36~\xdf\x97{&\xf9<'
[+] Decrypted plaintext at index 3968: b'\x9c;\xc6r\x1cIT \xa3X\xa8\x82\x97\x99VZ'
[+] Decrypted plaintext at index 4096: b'_>\xb6\xf3\xfb\xaa_&\x95\xaf2\xdd\xcbAZ\x03'
[+] Decrypted plaintext at index 4224: b'\xda\xb6\xad\xabj\xda\xb6\xad\xabj\xda\x92\xa10\x9c5'
[+] Decrypted plaintext at index 4352: b'\xf7 fH\xbaq\xab\x17\xa1\xc9kH:\xba6X'
[+] Decrypted plaintext at index 4480: b'Z\xda)\xafO\x13\xd4qk\x08\xac\xbd2\xd9\xd1\xba'
[+] Decrypted plaintext at index 4608: b'\x93\xb86\x0fL\xe7u\xc0`\xeas\x96\xd9\xe9\x19&'
[+] Decrypted plaintext at index 4736: b'\xc9m\xcf\xd9r\xc4_r\xe9\xa7e^\xe8\xd0\xdc\x9d'
[+] Decrypted plaintext at index 4864: b'\x02A\xa7V\xd5\xb5m[V\xd5\xb5m[V\xd4\x99'
[+] Decrypted plaintext at index 4992: b'\x19:\xd3\x156|\xd8\xbd\xea\xe7\x1a\xdfw\xe0M\x9f'
[+] Decrypted plaintext at index 5120: b'9\x94cQ\xaf-\xb3\xb3\x80\xf0R\xceEb\x11\xc6'
[+] Decrypted plaintext at index 5248: b'F\x92dQe\x99o\x14\xed\xbeSbn\x1e/\x99'
[+] Decrypted plaintext at index 5376: b'\xe1c\xba\x1b\xe9\x9b\x80:YNN\xbb\x85p\xbe\xcf'
[+] Decrypted plaintext at index 5504: b'V\xd5\xb5m[V\xd5\x92\n\xab\xd1\x9f\x8c\xaa\xab\xb2'
[+] Decrypted plaintext at index 5632: b'?\xaeG\xb4a\x9e\x8fP\xa1rR\xbc\x9dYX\x8b'
[+] Decrypted plaintext at index 5760: b'm\x82\x81\xbbf\xa4@\xe2\x8a\xe2\x9c\x88\x16\xf2@H'
[+] Decrypted plaintext at index 5888: b'\xdc\\m\x12a!\xa9p\xb0\x8ad\x00\xc7lFp'
[+] Decrypted plaintext at index 6016: b'0\x8c\x9cR!\xd7\xa4\xa7e+@\xcdf\x01Y\x9a'
[+] Decrypted plaintext at index 6144: b'{/\x8f\x9b\xd4<\xd5O\xa2\xf2kw\xcd\x98\xa8P'
[+] Decrypted plaintext at index 6272: b'4\xa4\xe8\xd1:*\x9a\xb2\xdb5\xca\x98p\xcd\x96\xb9'
[+] Decrypted plaintext at index 6400: b"\xcdk\x06\xc8k\x89\xdf\xc6'\n\\\xc2l\x15t#"
[+] Decrypted plaintext at index 6528: b'M\x83|\xca\xe3@\x9c\xca\xe0\nd\x8a\xc0\xc42s'
[+] Decrypted plaintext at index 6656: b'\\\xd5\xd1\xe0I\x83\xb2\xb9yL\x04!\x0c\x82H\x8c'
[+] Decrypted plaintext at index 6784: b'\xab`|\x8e\xc8\x84\xfa\x10\xbc\x935\xd2uy\x9f:'
[+] Decrypted plaintext at index 6912: b'\xae\xf0h\xca\x11\x16\x1b6h\x97VK\xd5\x00V\r'
[+] Decrypted plaintext at index 7040: b'\x97Oo\xe5Ze\xec~i\x9fG\xa3y^\x83\xd3'
[+] Decrypted plaintext at index 7168: b'\xd1\x04JP\xc95M\x8d\x9f\x93t\xe7\xe8\xbep\xcb'
[+] Decrypted plaintext at index 7296: b'\xd8\xc6\xabq\xb8\x96\xe6#Z:h\x92\xa5M\x9cC'
[+] Decrypted plaintext at index 7424: b'"&$B\x17F]%H\xc3\x06\xd8\x824\xc9\xe3'
[+] Decrypted plaintext at index 7552: b"\xb8\xe3\xab\xcfT\xc2\xde\xddO?\x8c'P\xf4\xda\xcc"
[+] Decrypted plaintext at index 7680: b'XY\xd8f\xdcv\xd5=\x18\xde~\xf5\x14\x9d\x08\xe7'
[+] Decrypted plaintext at index 7808: b'\r\x16^\xa6|\xf3\x9dp\xe2C\xd7\xc9a^\r\xcf'
[+] Decrypted plaintext at index 7936: b'<\xee\\\x08\xe1\xa7jV\x1b\xe8(\xea\\\xad]h'
[+] Decrypted plaintext at index 8064: b"'PLC\x17\x8eB\xbaJ+\xbb?\xa9\xad\x914"
[+] Decrypted plaintext at index 8192: b'\xb3\xf8\xc7gL\x1ayW\xa2?d\x95\xc3.~\x97'
[+] Decrypted plaintext at index 8320: b"/'G\x1d\xc7\xb2\xf2\x8e\xbb\xf8\xfd\x7f\x8d\xf3\xbb\xb9"
[+] Decrypted plaintext at index 8448: b'\xcf\xd3z0\xde{\xd9m\x87!\xc8k\x97\xd0\x1f8'
[+] Decrypted plaintext at index 8576: b'y\xec\xdb\xbfc\xc7\xd0\xe8x\xb7!\xd3\xf5\xe1\xc1\xb0'
[+] Decrypted plaintext at index 8704: b'J\x8c\xd9;,\xa0\xc4\x14H\x85\x88\x88B\xd8\x8e)'
[+] Decrypted plaintext at index 8832: b'u\xad.\xb9\x0f6/\xd9\xa3_U\x86\x9d\x15\xc8)'
......
[+] Decrypted plaintext at index 422016: b'\x80\xc6S\x1fO\xdd\x9b\x9b@`\xf9\x03\x83\xdf5\xa8'
[+] Last index: 422144
[+] Last block size: 64
[+] Program finished. Bye bye :)


"""
# ----------------------------------------------------------------------------------------

