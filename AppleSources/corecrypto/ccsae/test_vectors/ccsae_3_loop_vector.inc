/* Copyright (c) (2018,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

{
    .test_desc = "These test vectors find a valid point on the 3rd iteration of the hunting and pecking loop",
    .di = &ccsha256_ltc_di,
    .curve = &ccec_cp_256,
    .password = "7412ab9a49ca64cb8053",
    .password_identifier = NULL,
    .A = "322dae21ef20",
    .B = "7fcb3996888a",
    .rand = "152992ac5a69f0153b110945973bfd13d59a0d9ccc83bf65efa93a19910ea2b9",
    .mask = "f8a5e6ab6515110a437cf7b15a5b097ea92112150d76817d38ffaa22be20fa35",
    .commit = "ef9c2f4f3be5a927e340f9d9b11fbc7e920696f1f7008d7e20017ec05878cf0ff9a01c03f86c5916cb9d5a83f2a12718f9f2e9a96f6f93b32d07f89610af3249a2b0bdca91d313fe5b0d8d19f1f963cec941dd096dbbf900596c60e23a04ec33",
    .peer_commit = "e5fb1c38c676e432ca5bf28930f8ec63300ca4d0faa7edce37baf1982a61c8d1112547bcd58ccf553c36d63820516ebb0964f3f135c6bcdbd2056e3eb2728b54a6a2e18758431b7f1acc4721738a138f5855e75de7a541832aa16186d93a5a8f",
    .send_confirm = "0000",
    .confirm = "98edaf6827b7678d6195035bb2f9c95d00a91d0ce8d929905fc8edb323e88a4e",
    .peer_send_confirm = "0000",
    .peer_confirm = "f2a4661bc92b3e9e860703fa38605fc75f1960c5333b2fb3c5eb7e762e1258a7",
    .kck = "5bfd9fd7f0eb482f1283be863084377c4413117351281d69273e1db579f1c711",
    .pmk = "dbee68503b5e33f8dc754875fe506bc0b494617ed545d65566b1b8ff894f3ae9",
    .pmkid = "d5974b89025c8d59ad9cec62e218a8e2",
},
