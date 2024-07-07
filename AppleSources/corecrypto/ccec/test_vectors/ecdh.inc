/* Copyright (c) (2016,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
*/

// From http://tools.ietf.org/html/rfc6979#page-29

/*
struct ccech_vector {
    ccec_const_cp_t (*curve)(void); // curve
    const char *QCAVSx;     // CAVS public key Q, x coordinate
    const char *QCAVSy;     // CAVS public key Q, y coordinate
    const char *dIUT;		// CAVS private key
    const char *QIUTx;		// IUT public key Q, x coordinate
    const char *QIUTy;		// IUT public key Q, x coordinate
const char *ZIUT;        // IUT shared secret
    const int status
};
*/
{
.curve=&ccec_cp_192,
.QCAVSx = "42ea6dd9969dd2a61fea1aac7f8e98edcc896c6e55857cc0",
.QCAVSy = "dfbe5d7c61fac88b11811bde328e8a0d12bf01a9d204b523",
.dIUT = "f17d3fea367b74d340851ca4270dcb24c271f445bed9d527",
.QIUTx = "b15053401f57285637ec324c1cd2139e3a67de3739234b37",
.QIUTy = "f269c158637482aad644cd692dd1d3ef2c8a7c49e389f7f6",
.ZIUT = "803d8ab2e5b6e6fca715737c3a82f7ce3c783124f6d51cd0",
.status=0,
},
{
.curve=&ccec_cp_224,
.QCAVSx = "af33cd0629bc7e996320a3f40368f74de8704fa37b8fab69abaae280",
.QCAVSy = "882092ccbba7930f419a8a4f9bb16978bbc3838729992559a6f2e2d7",
.dIUT = "8346a60fc6f293ca5a0d2af68ba71d1dd389e5e40837942df3e43cbd",
.QIUTx = "8de2e26adf72c582d6568ef638c4fd59b18da171bdf501f1d929e048",
.QIUTy = "4a68a1c2b0fb22930d120555c1ece50ea98dea8407f71be36efac0de",
.ZIUT = "7d96f9a3bd3c05cf5cc37feb8b9d5209d5c2597464dec3e9983743e8",
.status=0,
},
{
.curve=&ccec_cp_256,
.QCAVSx = "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287",
.QCAVSy = "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac",
.dIUT = "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534",
.QIUTx = "ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230",
.QIUTy = "28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141",
.ZIUT = "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b",
.status=0,
},
{ // Special point with very small X
.curve=&ccec_cp_256,
.QCAVSx = "5",
.QCAVSy = "459243b9aa581806fe913bce99817ade11ca503c64d9a3c533415c083248fbcc",
.dIUT = "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534",
.QIUTx = "ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230",
.QIUTy = "28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141",
.ZIUT = "1915fba988b4dd95aa992b5ca75d0afbe581966b84877c5149bfe0165dfd6726",
.status=0,
},
{ // Same as previous, by replacing 5 by p+5. The point is therefore on the curve
// but it should be rejected since p+5>p.
.curve=&ccec_cp_256,
.QCAVSx = "ffffffff00000001000000000000000000000001000000000000000000000004",
.QCAVSy = "459243b9aa581806fe913bce99817ade11ca503c64d9a3c533415c083248fbcc",
.dIUT = "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534",
.QIUTx = "ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230",
.QIUTy = "28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141",
.ZIUT = "1915fba988b4dd95aa992b5ca75d0afbe581966b84877c5149bfe0165dfd6726",
.status=-1, // Failure
},
{ // Special point with very small Y
.curve=&ccec_cp_256,
.QCAVSx = "9e78d4ef60d05f750f6636209092bc43cbdd6b47e11a9de20a9feb2a50bb96c",
.QCAVSy = "1",
.dIUT = "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534",
.QIUTx = "ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230",
.QIUTy = "28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141",
.ZIUT = "644d5c721a405f31ea1af0f4939c3f007c1c78ae4782c953af8ceb1b717114d2",
.status=0,
},
{ // Same as previous, by replacing 1 by p+1. The point is therefore on the curve
// but it should be rejected since p+1>p.
.curve=&ccec_cp_256,
.QCAVSx = "9e78d4ef60d05f750f6636209092bc43cbdd6b47e11a9de20a9feb2a50bb96c",
.QCAVSy = "ffffffff00000001000000000000000000000001000000000000000000000000",
.dIUT = "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534",
.QIUTx = "ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230",
.QIUTy = "28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141",
.ZIUT = "644d5c721a405f31ea1af0f4939c3f007c1c78ae4782c953af8ceb1b717114d2",
.status=-1,
},
{
.curve=&ccec_cp_384,
.QCAVSx = "a7c76b970c3b5fe8b05d2838ae04ab47697b9eaf52e764592efda27fe7513272734466b400091adbf2d68c58e0c50066",
.QCAVSy = "ac68f19f2e1cb879aed43a9969b91a0839c4c38a49749b661efedf243451915ed0905a32b060992b468c64766fc8437a",
.dIUT = "3cc3122a68f0d95027ad38c067916ba0eb8c38894d22e1b15618b6818a661774ad463b205da88cf699ab4d43c9cf98a1",
.QIUTx = "9803807f2f6d2fd966cdd0290bd410c0190352fbec7ff6247de1302df86f25d34fe4a97bef60cff548355c015dbb3e5f",
.QIUTy = "ba26ca69ec2f5b5d9dad20cc9da711383a9dbe34ea3fa5a2af75b46502629ad54dd8b7d73a8abb06a3a3be47d650cc99",
.ZIUT = "5f9d29dc5e31a163060356213669c8ce132e22f57c9a04f40ba7fcead493b457e5621e766c40a2e3d4d6a04b25e533f1",
.status=0,
},
{
.curve=&ccec_cp_521,
.QCAVSx = "000000685a48e86c79f0f0875f7bc18d25eb5fc8c0b07e5da4f4370f3a9490340854334b1e1b87fa395464c60626124a4e70d0f785601d37c09870ebf176666877a2046d",
.QCAVSy = "000001ba52c56fc8776d9e8f5db4f0cc27636d0b741bbe05400697942e80b739884a83bde99e0f6716939e632bc8986fa18dccd443a348b6c3e522497955a4f3c302f676",
.dIUT = "0000017eecc07ab4b329068fba65e56a1f8890aa935e57134ae0ffcce802735151f4eac6564f6ee9974c5e6887a1fefee5743ae2241bfeb95d5ce31ddcb6f9edb4d6fc47",
.QIUTx = "000000602f9d0cf9e526b29e22381c203c48a886c2b0673033366314f1ffbcba240ba42f4ef38a76174635f91e6b4ed34275eb01c8467d05ca80315bf1a7bbd945f550a5",
.QIUTy = "000001b7c85f26f5d4b2d7355cf6b02117659943762b6d1db5ab4f1dbc44ce7b2946eb6c7de342962893fd387d1b73d7a8672d1f236961170b7eb3579953ee5cdc88cd2d",
.ZIUT = "005fc70477c3e63bc3954bd0df3ea0d1f41ee21746ed95fc5e1fdf90930d5e136672d72cc770742d1711c3c3a4c334a0ad9759436a4d3c5bf6e74b9578fac148c831",
.status=0,
},
{
.curve=NULL,
},

