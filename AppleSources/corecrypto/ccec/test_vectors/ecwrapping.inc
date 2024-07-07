/* Copyright (c) (2015,2016,2019,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
*/

/*
struct ccecwrapping_vector {
ccec_const_cp_t (*cp)(void);
const struct ccec_rfc6637_curve *curve;
const struct ccec_rfc6637_wrap *wrap;
const struct ccec_rfc6637_unwrap *unwrap;
unsigned long flags;
uint8_t alg;
const char *str_der_priv_key;
const char *str_x963_pub_key;
const char *str_der_diversified_pub_key;
const char *str_key;
const char *str_der_ephemeral_priv_key; // Used within wrapping
const char *str_wrapped_key;
const char *str_fingerprint;
};

*/
{
    .cp=&ccec_cp_256,
    .curve=&ccec_rfc6637_dh_curve_p256,
    .wrap=&ccec_rfc6637_wrap_sha256_kek_aes128,
    .unwrap=&ccec_rfc6637_unwrap_sha256_kek_aes128,
    .flags=0,
    .alg=9,
    // private key
    .str_der_priv_key="30250201010420a05cd14749bea3f3d14c92dc438e45e351efe860360c431705b7d42410581843",
    // Public key
    .str_x963_pub_key="047f70c0a8184cdcaea5db20ba8fed17e47bdefb744d575ec449130af37edade658ae7ee35d20e8897911c9f564be33d9a94bc1e5c927b1aa07ff750d2d11c2971",
    // Diversified public key
    // Key to be wrapped
    .str_key="175D179875780EE3270F6C0DCE3E1151D4E25CE567FDC8AB2C2DB264AF8F91BC",
    // Wrapped key
    /* length i bits MSB */
    .str_wrapped_key="0208"
    /* ephemeral dh key */
    "041dd218650c7ead5d5c8f2eea8ad20e108085173a78723b115f8afeac374c71052c87b55999b3f573d0b4b3db2008ac2e6d67e4718525d993a3bb8832face0c61"
    /* aes-wrap key size */
    "30"
    /* aes wrapped data */
    "5be3f8fc2639c9f41aa7e8b5aeb535c9cf0b1d3f5dd52092e786236a212751dffeb1590d08091633c1bf799d46757350",
    // Fingerprint
    .str_fingerprint="C3DC0554FF5EEF325081D6E377CEB7A34089AB73"
},
// Test case 1 from 23493000
{
    .cp=&ccec_cp_256,
    .curve=&ccec_rfc6637_dh_curve_p256,
    .wrap=&ccec_rfc6637_wrap_sha256_kek_aes128,
    .unwrap=&ccec_rfc6637_unwrap_sha256_kek_aes128,
    .flags=CCEC_RFC6637_COMPACT_KEYS,
    .alg=1,
    // private key
    .str_der_priv_key="30250201010420bfbe27251a23b3663f0f1e651dc0ba780b1dac12fc43bc8994ce5c637ad9b0c4",
    // Public key
    .str_x963_pub_key="04c7de9f744fee342d8b3bb5cbfbe1d5eae7b68d3eee6dc5b9f9c0cf7ce271daca63e002bc48c8be820a5f70fea39806b457590d1eb03067672920a37f46089602",
    // Diversified public key
    .str_der_diversified_pub_key="308186044104fed3b2ea41004f6bf6afccf71e2ab344b8a11d1a5499b5e65169ea018c95f15f4d42bf5ad384ae85578576eb7e0e7c1270f66ed1ed9ce35330e6bf5d4d824d8d0441047bafba6606c989a590e36f6a9806d5f93c7709a4c7d3d43389ccb041a598cdeb21047091e902fc751be9c9804dcc1a27f13b14d064e4408d8a92143f6c75ff76",
    // Key to be wrapped
    .str_key="72616e646f6d54657374",
    // Wrapped key
    .str_wrapped_key="010096d3d3827030b6dc824e6bbc87448196d2d736385aea78f8119e5fddc6ecb12030027a286fc5f306543a638eef84024455c446ea9ada45f29bb4e91b1637c579d45510721002c63272b27e6c7ae99fc79e",
    // Fingerprint
    .str_fingerprint="66696e6765727072696e74000000000000000000"
},
// Test case 2 from 23493000
{   .cp=&ccec_cp_256,
    .curve=&ccec_rfc6637_dh_curve_p256,
    .wrap=&ccec_rfc6637_wrap_sha256_kek_aes128,
    .unwrap=&ccec_rfc6637_unwrap_sha256_kek_aes128,
    .flags=CCEC_RFC6637_COMPACT_KEYS,
    .alg=1,
    // private key
    .str_der_priv_key="30250201010420bfbe27251a23b3663f0f1e651dc0ba780b1dac12fc43bc8994ce5c637ad9b0c4",
    // Public key
    .str_x963_pub_key="04c7de9f744fee342d8b3bb5cbfbe1d5eae7b68d3eee6dc5b9f9c0cf7ce271daca63e002bc48c8be820a5f70fea39806b457590d1eb03067672920a37f46089602",
    // Diversified public key
    .str_der_diversified_pub_key="308186044104ddc7d6db9b3de6c39e6e8f6b382c1eb4a8e0a8100030ec2c0c64bf32c2ea55ad58bae41a09f8bef2ca1dfaebd0261c37af689dedcbb11db8eb98a79908c3e1b104410438599f292464494a40107751cf314cd19903cd3bb5e2a5449f713067d835aa2bc545b54c9c27c322a6b6ebdfc49b679fda64cf8a3a0611d7e9b7eae930bcb1d9",
    // Key to be wrapped
    .str_key="72616e646f6d54657374",
    // Wrapped key
    .str_wrapped_key="0100cfd64ccc74b62a2e1e0de0ad5760f2d480ff5a8f33957e343fb46eb6e582fb4b3099cf6d0f70bfb11b8e0b1ac968f97c3fe87f41c5daf3b40aeaf5d6f4001cf77432883d618214015a5f8b4601c506095a",
    // Fingerprint
    .str_fingerprint="66696e6765727072696e74000000000000000000"
},
// Test case 3 from 23493000
{   .cp=&ccec_cp_256,
    .curve=&ccec_rfc6637_dh_curve_p256,
    .wrap=&ccec_rfc6637_wrap_sha256_kek_aes128,
    .unwrap=&ccec_rfc6637_unwrap_sha256_kek_aes128,
    .flags=CCEC_RFC6637_COMPACT_KEYS,
    .alg=1,
    // private key
    .str_der_priv_key="30250201010420bfbe27251a23b3663f0f1e651dc0ba780b1dac12fc43bc8994ce5c637ad9b0c4",
    // Public key
    .str_x963_pub_key="04c7de9f744fee342d8b3bb5cbfbe1d5eae7b68d3eee6dc5b9f9c0cf7ce271daca63e002bc48c8be820a5f70fea39806b457590d1eb03067672920a37f46089602",
    // Diversified public key
    .str_der_diversified_pub_key="30818604410400d69325f0374acca60216651011fa9c96f4d0bbe23d06da587a1473400f5156005467a0921ea12a1d306bc6a5db2e27ec603b054536a96e60fe96be300f8aeb044104ed1a836979ff2bf7cc7693ab19c2d289d7693c975f4048ad2cb61f38f2f41ee59ceff88aecd7d6a389c9b59dd281b007f64042490057350c30a7b570f8afa0d5",
    // Key to be wrapped
    .str_key="72616e646f6d54657374",
    // Wrapped key
    .str_wrapped_key="01009a2b254a59dbd7104652a78d20fe5af5b7d159682659820e52f01b1ea4256dad30a99950d40c606972db5881a2da3cb9593318b6377b3155d7e0201534da64cf9c5a89da261437aac5bb289f7b66a5ccda",
    // Fingerprint
    .str_fingerprint="66696e6765727072696e74000000000000000000"
},
// Test case 4 from 23493000
{   .cp=&ccec_cp_256,
    .curve=&ccec_rfc6637_dh_curve_p256,
    .wrap=&ccec_rfc6637_wrap_sha256_kek_aes128,
    .unwrap=&ccec_rfc6637_unwrap_sha256_kek_aes128,
    .flags=CCEC_RFC6637_COMPACT_KEYS,
    .alg=1,
    // private key
    .str_der_priv_key="30250201010420bfbe27251a23b3663f0f1e651dc0ba780b1dac12fc43bc8994ce5c637ad9b0c4",
    // Public key
    .str_x963_pub_key="04c7de9f744fee342d8b3bb5cbfbe1d5eae7b68d3eee6dc5b9f9c0cf7ce271daca63e002bc48c8be820a5f70fea39806b457590d1eb03067672920a37f46089602",
    // Diversified public key
    .str_der_diversified_pub_key="30818604410409fbdbee0f794385158960ff37cd71a5eafc062170b36efd1d47595172da26564ae1ffe73df0a1c28aadcd6e1a34c65f075d455775d13fd968ba456f21f3a89304410400bf374625ab6bc53ca09c80bc276bd736f32e0af951bb160bfff3eb630e163f0033e9c95fdc86ded6a2e068ac03159932ca06e97dc10595f2867a4f1c83503f",
    // Key to be wrapped
    .str_key="72616e646f6d54657374",
    // Wrapped key
    .str_wrapped_key="010022fb5583bc4134cfa8f09bb810c1b4d66dac1c7cc38c95426fd9ae668107006c30353c59f6f403e8c61f5e01c748a362b532437ebd6b50b8f846222fb6fea6edd9d8f3349c43063fc0c4ee2a7b938c6f89",
    // Fingerprint
    .str_fingerprint="66696e6765727072696e74000000000000000000"
},
// Test case 5 from 23493000
{   .cp=&ccec_cp_256,
    .curve=&ccec_rfc6637_dh_curve_p256,
    .wrap=&ccec_rfc6637_wrap_sha256_kek_aes128,
    .unwrap=&ccec_rfc6637_unwrap_sha256_kek_aes128,
    .flags=CCEC_RFC6637_COMPACT_KEYS,
    .alg=1,
    // private key
    .str_der_priv_key="30250201010420bfbe27251a23b3663f0f1e651dc0ba780b1dac12fc43bc8994ce5c637ad9b0c4",
    // Public key
    .str_x963_pub_key="04c7de9f744fee342d8b3bb5cbfbe1d5eae7b68d3eee6dc5b9f9c0cf7ce271daca63e002bc48c8be820a5f70fea39806b457590d1eb03067672920a37f46089602",
    // Diversified public key
    .str_der_diversified_pub_key="308186044104510499484243f127511b99cf4d03b5db2cfe713dd5023785c474ac96b7f22a59207a7c0502cdf9549dbcdc01b007c750cd80e3405b08c3704efeed09858d525004410416cb939ae75f25cd383eef2be10e873677f0df4f5cbf0b3f4632b8b7b92f950690efc1f6248932dcadea114a85bd77bc9b92d93f1310b103e1ebe0613a610367",
    // Key to be wrapped
    .str_key="72616e646f6d54657374",
    // ephemeral private key created within the wrap procedure
    .str_der_ephemeral_priv_key="3025020101042052cdd8805f67f1a1778d6838cef9867504ea0ffa5294643f0e8aa69d96db0efe",
    // Wrapped key
    .str_wrapped_key="01003be129716fa544fe43236ba037baa4f34fc902dd699505666e10cd6ee0bd523a309b2e2c7c5dc610ef6a1543e963255c145234dd536cb0480064c79ecabe8c8cdad999c25473b012b854abfa9523b7d41f",
    // Fingerprint
    .str_fingerprint="66696e6765727072696e74000000000000000000"
},
// Test case 6 from 23493000
{   .cp=&ccec_cp_256,
    .curve=&ccec_rfc6637_dh_curve_p256,
    .wrap=&ccec_rfc6637_wrap_sha256_kek_aes128,
    .unwrap=&ccec_rfc6637_unwrap_sha256_kek_aes128,
    .flags=CCEC_RFC6637_COMPACT_KEYS,
    .alg=1,
    // private key
    .str_der_priv_key="30250201010420bfbe27251a23b3663f0f1e651dc0ba780b1dac12fc43bc8994ce5c637ad9b0c4",
    // Public key
    .str_x963_pub_key="04c7de9f744fee342d8b3bb5cbfbe1d5eae7b68d3eee6dc5b9f9c0cf7ce271daca63e002bc48c8be820a5f70fea39806b457590d1eb03067672920a37f46089602",
    // Diversified public key
    .str_der_diversified_pub_key="3081860441044019963347e9421b415ef7303364eed9d424e15f401955da258508e723e00bf816111d85bbb6c698ebfd49e49d32d98913c26a7b1afd1d84f6f575fbe1c20a0b04410438785a513b6c351e23d6c9493defa4af6ab479724b8d50b0da18cc415306b30aef11d7da4c57afa5343f131c8a3c155295f14f4e49f6580fc25bb35d8ebd603d",
    // Key to be wrapped
    .str_key="72616e646f6d54657374",
    // ephemeral private key created within the wrap procedure
    .str_der_ephemeral_priv_key="30250201010420220472cf7e78f259d8b6ebb59ca96b5ad537d1d3f627710292fdf3d70e941bdf",
    // Wrapped key
    .str_wrapped_key="010017a63286851831c058d06d5d317f0ef8da1864e6833e201fbea3c3f15642f4a930da1c32ab22995cdcc32c8bac51c139d8cb17214b88e343489df7e4565be0f08f5051e00361b2b635483ebfdbb295b585",
    // Fingerprint
    .str_fingerprint="66696e6765727072696e74000000000000000000"
},
// Test case 7
{   .cp=&ccec_cp_256,
    .curve=&ccec_rfc6637_dh_curve_p256,
    .wrap=&ccec_rfc6637_wrap_sha256_kek_aes128,
    .unwrap=&ccec_rfc6637_unwrap_sha256_kek_aes128,
    .flags=0,
    .alg=9,
    // private key
    .str_der_priv_key="30250201010420a05cd14749bea3f3d14c92dc438e45e351efe860360c431705b7d42410581843",
    // Public key
    .str_x963_pub_key="047f70c0a8184cdcaea5db20ba8fed17e47bdefb744d575ec449130af37edade658ae7ee35d20e8897911c9f564be33d9a94bc1e5c927b1aa07ff750d2d11c2971",
    .str_diversify_entropy="ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325500000000000000000", // (q-1)*2^64
    .str_der_diversified_pub_key="3081860441046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f50441047f70c0a8184cdcaea5db20ba8fed17e47bdefb744d575ec449130af37edade658ae7ee35d20e8897911c9f564be33d9a94bc1e5c927b1aa07ff750d2d11c2971",
    // Diversified public key
    // Key to be wrapped
    .str_key="175D179875780EE3270F6C0DCE3E1151D4E25CE567FDC8AB2C2DB264AF8F91BC",
    // Wrapped key
    /* length i bits MSB */
    .str_wrapped_key="0208"
    /* ephemeral dh key */
    "041dd218650c7ead5d5c8f2eea8ad20e108085173a78723b115f8afeac374c71052c87b55999b3f573d0b4b3db2008ac2e6d67e4718525d993a3bb8832face0c61"
    /* aes-wrap key size */
    "30"
    /* aes wrapped data */
    "5be3f8fc2639c9f41aa7e8b5aeb535c9cf0b1d3f5dd52092e786236a212751dffeb1590d08091633c1bf799d46757350",
    // Fingerprint
    .str_fingerprint="C3DC0554FF5EEF325081D6E377CEB7A34089AB73"
},

// Diversification KAT 1
{   .cp=&ccec_cp_256,
    .curve=&ccec_rfc6637_dh_curve_p256,
    .wrap=&ccec_rfc6637_wrap_sha256_kek_aes128,
    .unwrap=&ccec_rfc6637_unwrap_sha256_kek_aes128,
    .flags=CCEC_RFC6637_COMPACT_KEYS,
    .alg=1,
    // private key
    .str_der_priv_key="30250201010420bfbe27251a23b3663f0f1e651dc0ba780b1dac12fc43bc8994ce5c637ad9b0c4",
    // Public key
    .str_x963_pub_key="04c7de9f744fee342d8b3bb5cbfbe1d5eae7b68d3eee6dc5b9f9c0cf7ce271daca63e002bc48c8be820a5f70fea39806b457590d1eb03067672920a37f46089602",
    .str_diversify_entropy="b9ddbb14896a26e4bf05b024e0d6c707335a97c27e6e57d172424ab33baff7f28d32949a2bb5bc64",
    // Diversified public key
    .str_der_diversified_pub_key="30818604410494ec20e2f0bb6ff25a10061b4222259e43963fc43a254812551b8790be5a85f155d37d066fa30f6db1688dac3ebec3ba19b21be5ea182922fd3df0081c0bc29a0441049b7341ce062e331c81d16e48206827fa95f8ce04e4792ee40406efbb63412bb2e195ad57a679be7890ffbb405ba1f41718ae53e5923fff8bbcab080f0652cbdf",
    // Key to be wrapped
    .str_key="72616e646f6d54657374",
    // ephemeral private key created within the wrap procedure
    .str_der_ephemeral_priv_key="30250201010420bce0290841cdb64236c3f35c703ca2559453197eb8670ddd445f4dc2458d77a0",
    // Wrapped key
    .str_wrapped_key="010080e5ab8192a303d89bf2d151cb04025e14b45b0a5762240ce4133d7bb123d3e230fc1b9ca98f5a19444e3ef2c23bb01575659cc1d184e8d56c2f74ec42c8ce428a7ce77cde76533600eee54e928ed93294",
    // Fingerprint
    .str_fingerprint="66696e6765727072696e74000000000000000000"
},
// Diversification KAT 2
{   .cp=&ccec_cp_256,
    .curve=&ccec_rfc6637_dh_curve_p256,
    .wrap=&ccec_rfc6637_wrap_sha256_kek_aes128,
    .unwrap=&ccec_rfc6637_unwrap_sha256_kek_aes128,
    .flags=CCEC_RFC6637_COMPACT_KEYS,
    .alg=1,
    // private key
    .str_der_priv_key="30250201010420bfbe27251a23b3663f0f1e651dc0ba780b1dac12fc43bc8994ce5c637ad9b0c4",
    // Public key
    .str_x963_pub_key="04c7de9f744fee342d8b3bb5cbfbe1d5eae7b68d3eee6dc5b9f9c0cf7ce271daca63e002bc48c8be820a5f70fea39806b457590d1eb03067672920a37f46089602",
    .str_diversify_entropy="e6f51febf2b6651e6a198edc14c5bddfc5bc7362c414c45bcd416bc4ec339808a1c3631b43b488d3",
    // Diversified public key
    .str_der_diversified_pub_key="308186044104835480b3f8d2a835cd2e163c45cea61f95bbbf2bd39982201b00c838dd05276fb64e669ff98891ddab29d9a7b9e8cf8579bfbf5e3c978cbf277a1da61def4d3904410493fdcf69899a6099e28fb1bf66cc30a405b61787364859316e1d56fd2c963115baed5213d4f5c6bb3dd81446ddf5c23498b39551fa9f1818ea735d6b6857860f",
    // Key to be wrapped
    .str_key="72616e646f6d54657374",
    // ephemeral private key created within the wrap procedure
    .str_der_ephemeral_priv_key="3025020101042028a28eb3be191a564d7b59829da54e28028ee7fe1e06928598d85e2f9c678a0d",
    // Wrapped key
    .str_wrapped_key="01006cd38f8305c33a065c74272bd9bd36704d8a30402e9d28df7ff6d648f813818b305f767b3c05a14550ee193a6ee32fbce5b30091f8c3f81a4a916ffe60e9924716f78b320ae437d2d5a1895d6019e95939",
    // Fingerprint
    .str_fingerprint="66696e6765727072696e74000000000000000000"
},
// Diversification KAT 3
{   .cp=&ccec_cp_256,
    .curve=&ccec_rfc6637_dh_curve_p256,
    .wrap=&ccec_rfc6637_wrap_sha256_kek_aes128,
    .unwrap=&ccec_rfc6637_unwrap_sha256_kek_aes128,
    .flags=CCEC_RFC6637_COMPACT_KEYS,
    .alg=1,
    // private key
    .str_der_priv_key="30250201010420bfbe27251a23b3663f0f1e651dc0ba780b1dac12fc43bc8994ce5c637ad9b0c4",
    // Public key
    .str_x963_pub_key="04c7de9f744fee342d8b3bb5cbfbe1d5eae7b68d3eee6dc5b9f9c0cf7ce271daca63e002bc48c8be820a5f70fea39806b457590d1eb03067672920a37f46089602",
    .str_diversify_entropy="6e0ed323fe92ccb88664ba90cc53c342d5ad59d09a6f26b291343bfb9eeea181407cca60a2d04d8b",
    // Diversified public key
    .str_der_diversified_pub_key="308186044104d871b2c34e67263487b6e507894ed6a1dca225924cbcbc0e140ffa2b04fc78ddbd78bf9a51215f375e48c6b962f51fff83c93c3a1129246527857620281ab123044104e70345ea1c73b6e007542e52f82ef9283692d6b4d9fb942a3add717ee2c98dfba6d72350a23ee03ca89b977c7d1375966ab2b48068e9c22dbed70236b860abcb",
    // Key to be wrapped
    .str_key="72616e646f6d54657374",
    // ephemeral private key created within the wrap procedure
    .str_der_ephemeral_priv_key="30250201010420a937de70f4ea770dcb310e4d289052e2262cf4389f630ca953100aeebf74172f",
    // Wrapped key
    .str_wrapped_key="0100a03fed3a57b325277ae872a69ded94c200f9ac3d756d509680310fa28c019f8d300252520574ec7bc3ab46abbb85b0fbb8c2b006de10b22a827b9163e6b44d4b4fd48fde50b09811020434385ab7c51a3c",
    // Fingerprint
    .str_fingerprint="66696e6765727072696e74000000000000000000"
},
// Diversification KAT 4
{   .cp=&ccec_cp_256,
    .curve=&ccec_rfc6637_dh_curve_p256,
    .wrap=&ccec_rfc6637_wrap_sha256_kek_aes128,
    .unwrap=&ccec_rfc6637_unwrap_sha256_kek_aes128,
    .flags=CCEC_RFC6637_COMPACT_KEYS,
    .alg=1,
    // private key
    .str_der_priv_key="30250201010420bfbe27251a23b3663f0f1e651dc0ba780b1dac12fc43bc8994ce5c637ad9b0c4",
    // Public key
    .str_x963_pub_key="04c7de9f744fee342d8b3bb5cbfbe1d5eae7b68d3eee6dc5b9f9c0cf7ce271daca63e002bc48c8be820a5f70fea39806b457590d1eb03067672920a37f46089602",
    .str_diversify_entropy="05bd185a3677dc3590f8317d6a386e5961999380034186b59c69510bc9c37cf41b5a345939816f3a",
    // Diversified public key
    .str_der_diversified_pub_key="3081860441046e82cf0e2817fb796e2abd2bdb484c5b5d2b78f632f9da04e8cbd59b25eb67679831dd7c7f2c5ce28df33c8bc77220fff32050229458c6e5c0b6fab30215362c04410476c698f46dc1af6fd573745962c60d11ba14230b94fa93ddaaaf15afe176dcccb923937aca981a44974c906315d429f1b48bb448bc39b1696caab77c3c7d3b9c",
    // Key to be wrapped
    .str_key="72616e646f6d54657374",
    // ephemeral private key created within the wrap procedure
    .str_der_ephemeral_priv_key="302502010104207cb877dedc16ff428d88ac5c0d7d8f68ff569df93e09da380d7818e19c4e70bf",
    // Wrapped key
    .str_wrapped_key="01000c651c11b08dbbb119a84f880c2fa4a03795957c669d5c3a1c51db69624ad0be3060750b8c2a217759d5df1d49e374f55849d2dea53dc26692d401738be81d04662318aa26543419f1b2cf5d81f3bdf865",
    // Fingerprint
    .str_fingerprint="66696e6765727072696e74000000000000000000"
},

