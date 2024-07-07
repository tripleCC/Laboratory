/* Copyright (c) (2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
*/

// P192, SHA1, no diversification
{
    .di=di_SHA1,
    .curve=&ccec_cp_192,
    .mac_nbytes = 16,
    .key_nbytes = 16,
    // Decryption private key
    .dec_priv_key = "9ebc0975033b0330bc461613ddd59a9e42ea06efb1997dc6",
    //Qsx = 5f906901924c87fa6b24ec4b8f6fd22bb8b78f30f6a32738
    //Qsy = f00cb3613ad1ec9bb667db4167f8464749c519eb3e12acde
    // Ephemeral private key
    .eph_priv_key = "5c7d5155376ed3cef3f851314cca479187771c89edd7ad13",
    //Qex = fd2af653b5de1437ba0c4b3b301e00909aeee462a01a558a
    //Qey = 48d1ea67729bc3ee1a55d3e889865777c5ca99e2045ab4c9
    .Z = "f1b9ec8da4c8a8d7ed27bfe2a798646cb64fcc37f2504cf7",
    //KDF(Z,00000001,"") = 99fbfc5106a564cf425d64a46d068327c0ba351e59a21397e7b8ed7cab5a06f6
    .message = "f04e8860e6b86552cfa933c387",
    // Encrypted message = b0478ecce0902c50be9e30ae1a
    // Mac Tag = 8f733216360bdccdbf30bf62bc053e9a
    .cipher = "04fd2af653b5de1437ba0c4b3b301e00909aeee462a01a558a48d1ea67729bc3ee1a55d3e889865777c5ca99e2045ab4c9"
        "b0478ecce0902c50be9e30ae1a"
        "8f733216360bdccdbf30bf62bc053e9a",
    .compact_cipher = "fd2af653b5de1437ba0c4b3b301e00909aeee462a01a558a"
        "b0478ecce0902c50be9e30ae1a"
        "8f733216360bdccdbf30bf62bc053e9a",
    .options=ECIES_EXPORT_PUB_STANDARD,
    .sharedInfo1="",
    .sharedInfo2="",
},
// P192, SHA1, no diversification, Key length > hash output
{
.di=di_SHA1,
.curve=&ccec_cp_192,
.mac_nbytes = 16,
.key_nbytes = 32,
// Decryption private key
.dec_priv_key = "9ebc0975033b0330bc461613ddd59a9e42ea06efb1997dc6",
//Qsx = 5f906901924c87fa6b24ec4b8f6fd22bb8b78f30f6a32738
//Qsy = f00cb3613ad1ec9bb667db4167f8464749c519eb3e12acde
// Ephemeral private key
.eph_priv_key = "5c7d5155376ed3cef3f851314cca479187771c89edd7ad13",
//Qex = fd2af653b5de1437ba0c4b3b301e00909aeee462a01a558a
//Qey = 48d1ea67729bc3ee1a55d3e889865777c5ca99e2045ab4c9
.Z = "f1b9ec8da4c8a8d7ed27bfe2a798646cb64fcc37f2504cf7",
//KDF(Z,00000001,"") = 99fbfc5106a564cf425d64a46d068327c0ba351e59a21397e7b8ed7cab5a06f670ed3ecba7e58ace1742446851447cd2
.message = "f04e8860e6b86552cfa933c387",
// Encrypted message = f9ad905b1c77148c5dbc8d596e
// Mac Tag = 6b30f1a60cfdc31bf8c4e7db5258fd94
.cipher = "04fd2af653b5de1437ba0c4b3b301e00909aeee462a01a558a48d1ea67729bc3ee1a55d3e889865777c5ca99e2045ab4c9"
    "46fc82e9c0a3d4ffbd165239b6"
    "587f4212bdff713f3f23f7035633d406",
.compact_cipher = "fd2af653b5de1437ba0c4b3b301e00909aeee462a01a558a"
    "46fc82e9c0a3d4ffbd165239b6"
    "587f4212bdff713f3f23f7035633d406",
.options=ECIES_EXPORT_PUB_STANDARD,
.sharedInfo1="",
.sharedInfo2="",
},
// P192, SHA1, diversification SharedInfo 1 & 2
{
    .di=di_SHA1,
    .curve=&ccec_cp_192,
    .mac_nbytes = 16,
    .key_nbytes = 16,
    // Decryption private key
    .dec_priv_key = "9ebc0975033b0330bc461613ddd59a9e42ea06efb1997dc6",
    //Qsx = 5f906901924c87fa6b24ec4b8f6fd22bb8b78f30f6a32738
    //Qsy = f00cb3613ad1ec9bb667db4167f8464749c519eb3e12acde
    // Ephemeral private key
    .eph_priv_key = "5c7d5155376ed3cef3f851314cca479187771c89edd7ad13",
    //Qex = fd2af653b5de1437ba0c4b3b301e00909aeee462a01a558a
    //Qey = 48d1ea67729bc3ee1a55d3e889865777c5ca99e2045ab4c9
    .Z = "f1b9ec8da4c8a8d7ed27bfe2a798646cb64fcc37f2504cf7",
    //KDF(Z,00000001,"Test1") = b78241943751f594dde08fda421e67e90269ca2de6707c16c47238feac6d7f7c
    .message = "f04e8860e6b86552cfa933c387",
    // Key = b78241943751f594dde08fda421e67e9
    // IV = 0269ca2de6707c16c47238feac6d7f7c
    // Encrypted message = f5673e289e26483175f2d1292e
    // Mac Tag = 13e42229abe25855fee68836fdaa58bd
    .cipher = "04fd2af653b5de1437ba0c4b3b301e00909aeee462a01a558a48d1ea67729bc3ee1a55d3e889865777c5ca99e2045ab4c9"
        "f5673e289e26483175f2d1292e"
        "13e42229abe25855fee68836fdaa58bd",
    .compact_cipher = "fd2af653b5de1437ba0c4b3b301e00909aeee462a01a558a"
        "f5673e289e26483175f2d1292e"
        "13e42229abe25855fee68836fdaa58bd",
    .options=ECIES_EXPORT_PUB_STANDARD,
    .sharedInfo1="Test1",
    .sharedInfo2="Test2",
},
// P192, SHA1, diversification SharedInfo 1 = Ephemeral public point
{
    .di=di_SHA1,
    .curve=&ccec_cp_192,
    .mac_nbytes = 16,
    .key_nbytes = 16,
    // Decryption private key
    .dec_priv_key = "9ebc0975033b0330bc461613ddd59a9e42ea06efb1997dc6",
    //Qsx = 5f906901924c87fa6b24ec4b8f6fd22bb8b78f30f6a32738
    //Qsy = f00cb3613ad1ec9bb667db4167f8464749c519eb3e12acde
    // Ephemeral private key
    .eph_priv_key = "5c7d5155376ed3cef3f851314cca479187771c89edd7ad13",
    //Qex = fd2af653b5de1437ba0c4b3b301e00909aeee462a01a558a
    //Qey = 48d1ea67729bc3ee1a55d3e889865777c5ca99e2045ab4c9
    .Z = "f1b9ec8da4c8a8d7ed27bfe2a798646cb64fcc37f2504cf7",
    //KDF(Z,00000001,04fd2af653b5de1437ba0c4b3b301e00909aeee462a01a558a48d1ea67729bc3ee1a55d3e889865777c5ca99e2045ab4c9
    //    ) = 86db0e3606b7e886f19418f22ac309c3ed49763b5fe7839c58493865e7224239
    .message = "f04e8860e6b86552cfa933c387",
    // Key = 86db0e3606b7e886f19418f22ac309c3
    // IV = ed49763b5fe7839c58493865e7224239
    // Encrypted message = 9d4f3193db7e8a74ac84d83e61
    // Mac Tag = 591bdfba774708edffc0e4f59886cf2a
    .cipher = "04fd2af653b5de1437ba0c4b3b301e00909aeee462a01a558a48d1ea67729bc3ee1a55d3e889865777c5ca99e2045ab4c9"
        "9d4f3193db7e8a74ac84d83e61"
        "591bdfba774708edffc0e4f59886cf2a",
    // Key = d94f085d49ed84de12ad525a7a76f0b5
    // IV = 81411d95e09c28aa29154e50d6b586cb
    // Encrypted message = 1fd9f69b48b55d61b3afeabb36
    .compact_cipher= "fd2af653b5de1437ba0c4b3b301e00909aeee462a01a558a"
    "1fd9f69b48b55d61b3afeabb36"
    "faf67d6f1e0b88928de90f829bb3ffb7",
    .options=ECIES_EXPORT_PUB_STANDARD|ECIES_EPH_PUBKEY_IN_SHAREDINFO1,
    .sharedInfo1="",
    .sharedInfo2="",
},
// P192, SHA1, diversification Ephemeral public point + SharedInfo 1
{
.di=di_SHA1,
.curve=&ccec_cp_192,
.mac_nbytes = 16,
.key_nbytes = 16,
// Decryption private key
.dec_priv_key = "9ebc0975033b0330bc461613ddd59a9e42ea06efb1997dc6",
//Qsx = 5f906901924c87fa6b24ec4b8f6fd22bb8b78f30f6a32738
//Qsy = f00cb3613ad1ec9bb667db4167f8464749c519eb3e12acde
// Ephemeral private key
.eph_priv_key = "5c7d5155376ed3cef3f851314cca479187771c89edd7ad13",
//Qex = fd2af653b5de1437ba0c4b3b301e00909aeee462a01a558a
//Qey = 48d1ea67729bc3ee1a55d3e889865777c5ca99e2045ab4c9
.Z = "f1b9ec8da4c8a8d7ed27bfe2a798646cb64fcc37f2504cf7",
//KDF(Z,00000001,04fd2af653b5de1437ba0c4b3b301e00909aeee462a01a558a48d1ea67729bc3ee1a55d3e889865777c5ca99e2045ab4c9
//    ) = 86db0e3606b7e886f19418f22ac309c3ed49763b5fe7839c58493865e7224239
.message = "f04e8860e6b86552cfa933c387",
// Key = 86db0e3606b7e886f19418f22ac309c3
// IV = ed49763b5fe7839c58493865e7224239
// Encrypted message = 22513a1861d7819721d55ba9e2
// Mac Tag = 13ba05985136001b5dffcab04aeff682
.cipher = "04fd2af653b5de1437ba0c4b3b301e00909aeee462a01a558a48d1ea67729bc3ee1a55d3e889865777c5ca99e2045ab4c9"
"22513a1861d7819721d55ba9e2"
"13ba05985136001b5dffcab04aeff682",
// Key = d94f085d49ed84de12ad525a7a76f0b5
// IV = 81411d95e09c28aa29154e50d6b586cb
// Encrypted message = 8a19c1e2471ca2b26918c2e634
.compact_cipher= "fd2af653b5de1437ba0c4b3b301e00909aeee462a01a558a"
"8a19c1e2471ca2b26918c2e634"
"fb79445ac74e62e87d077c06f037e6bb",
.options=ECIES_EXPORT_PUB_STANDARD|ECIES_EPH_PUBKEY_AND_SHAREDINFO1,
.sharedInfo1="Test1",
.sharedInfo2="",
},
// P224, SHA224, no diversification
{
    .di=di_SHA224,
    .curve=&ccec_cp_224,
    .mac_nbytes = 16,
    .key_nbytes = 16,
    // Decryption private key
    .dec_priv_key = "11f0abdf4170f59ef4fca7871490f34902084ca84e299bedf0958401",
    //QeCAVSx = 60aa94e6b899069c6711221a332d3156168537a085011efe054d4cdf
    //QeCAVSy = 9ac019527cf4a7a4cd084856e80462f9fab7b8bd12b37d1b31bf03a5
    .eph_priv_key = "0e6d170df9aeeeaf4c14f734745ac83bf44b4b2e2419c44cb9dba4d2",
    //QsIUTx = 91ac459a13e4ee58306d02eb7cfb065d253ac0a07698dae19272c989
    //QsIUTy = d68c441be99223d911fe8da0277c10378943bc03725af4b77d844516
    .Z = "398b22a9a4c6da8f6677ef14994a057de60da78126bbd77e70e8e4e4",
    //KDF(Z,00000001,"") = 20f5ebd7d2c72dec6dbca62834f566c97859151870946815e3518f41610f329c
    .message = "f04e8860e6b86552cfa933c387",
    // Key = 20f5ebd7d2c72dec6dbca62834f566c9
    // IV = 7859151870946815e3518f41610f329c
    // Encrypted message = 3048b1f8a086dc6484afcc5325
    // Mac Tag = 8ab7d46530f39b90b58bdd3ae0576aaa
    .cipher = "0491ac459a13e4ee58306d02eb7cfb065d253ac0a07698dae19272c989d68c441be99223d911fe8da0277c10378943bc03725af4b77d844516"
        "3048b1f8a086dc6484afcc5325"
        "8ab7d46530f39b90b58bdd3ae0576aaa",
    .compact_cipher = "91ac459a13e4ee58306d02eb7cfb065d253ac0a07698dae19272c989"
        "3048b1f8a086dc6484afcc5325"
        "8ab7d46530f39b90b58bdd3ae0576aaa",
    .options=ECIES_EXPORT_PUB_STANDARD,
    .sharedInfo1="",
    .sharedInfo2="",
},
// P224, SHA224, diversification SharedInfo 1 & 2
{
    .di=di_SHA224,
    .curve=&ccec_cp_224,
    .mac_nbytes = 16,
    .key_nbytes = 16,
    .dec_priv_key = "11f0abdf4170f59ef4fca7871490f34902084ca84e299bedf0958401",
    //QeCAVSx = 60aa94e6b899069c6711221a332d3156168537a085011efe054d4cdf
    //QeCAVSy = 9ac019527cf4a7a4cd084856e80462f9fab7b8bd12b37d1b31bf03a5
    .eph_priv_key = "0e6d170df9aeeeaf4c14f734745ac83bf44b4b2e2419c44cb9dba4d2",
    //QsIUTx = 91ac459a13e4ee58306d02eb7cfb065d253ac0a07698dae19272c989
    //QsIUTy = d68c441be99223d911fe8da0277c10378943bc03725af4b77d844516
    .Z = "398b22a9a4c6da8f6677ef14994a057de60da78126bbd77e70e8e4e4",
    //KDF(Z,00000001,"Test1") = 0ac4e89cfc3fe709b3deed76b17105b85a2045c433f66d048858494591ace53e
    .message = "f04e8860e6b86552cfa933c387",
    // Key = 0ac4e89cfc3fe709b3deed76b17105b8
    // IV = 5a2045c433f66d048858494591ace53e
    // Encrypted message = 97c4c88bd774c6cde67fb1d8fe
    // Mac Tag = 5ffd23e5f8b0ab3391f240f771080b27
    .cipher = "0491ac459a13e4ee58306d02eb7cfb065d253ac0a07698dae19272c989d68c441be99223d911fe8da0277c10378943bc03725af4b77d844516"
    "97c4c88bd774c6cde67fb1d8fe"
    "5ffd23e5f8b0ab3391f240f771080b27",
    .compact_cipher = "91ac459a13e4ee58306d02eb7cfb065d253ac0a07698dae19272c989"
    "97c4c88bd774c6cde67fb1d8fe"
    "5ffd23e5f8b0ab3391f240f771080b27",
    .options=ECIES_EXPORT_PUB_STANDARD,
    .sharedInfo1="Test1",
    .sharedInfo2="Test2",
},
// P224, SHA224, diversification SharedInfo 1 = Ephemeral public point
{
    .di=di_SHA224,
    .curve=&ccec_cp_224,
    .mac_nbytes = 16,
    .key_nbytes = 16,
    .dec_priv_key = "11f0abdf4170f59ef4fca7871490f34902084ca84e299bedf0958401",
    //QeCAVSx = 60aa94e6b899069c6711221a332d3156168537a085011efe054d4cdf
    //QeCAVSy = 9ac019527cf4a7a4cd084856e80462f9fab7b8bd12b37d1b31bf03a5
    .eph_priv_key = "0e6d170df9aeeeaf4c14f734745ac83bf44b4b2e2419c44cb9dba4d2",
    //QsIUTx = 91ac459a13e4ee58306d02eb7cfb065d253ac0a07698dae19272c989
    //QsIUTy = d68c441be99223d911fe8da0277c10378943bc03725af4b77d844516
    .Z = "398b22a9a4c6da8f6677ef14994a057de60da78126bbd77e70e8e4e4",
    //KDF(Z,0491ac459a13e4ee58306d02eb7cfb065d253ac0a07698dae19272c989d68c441be99223d911fe8da0277c10378943bc03725af4b77d844516
    //    ) = c27836e8c57002dd0235a169261cba853df6168fe5d241fe40b053836368edba
    .message = "f04e8860e6b86552cfa933c387",
    // Key = c27836e8c57002dd0235a169261cba85
    // IV = 3df6168fe5d241fe40b053836368edba
    // Encrypted message = 72a97eff3a858b1ec5fece645e
    // Mac Tag = 3715feaed137e0cb53fd2d6a8010f21e
    .cipher = "0491ac459a13e4ee58306d02eb7cfb065d253ac0a07698dae19272c989d68c441be99223d911fe8da0277c10378943bc03725af4b77d844516"
        "72a97eff3a858b1ec5fece645e"
        "3715feaed137e0cb53fd2d6a8010f21e",
    .compact_cipher = "91ac459a13e4ee58306d02eb7cfb065d253ac0a07698dae19272c989"
        "79f44b4a9ae629a8fb6881b0e5"
        "c71838dfa4912a24ab772d4467e8290c",
    .options=ECIES_EXPORT_PUB_STANDARD|ECIES_EPH_PUBKEY_IN_SHAREDINFO1,
    .sharedInfo1="",
    .sharedInfo2="",
},
// P224, SHA224, diversification Ephemeral public point + SharedInfo 1
{
.di=di_SHA224,
.curve=&ccec_cp_224,
.mac_nbytes = 16,
.key_nbytes = 16,
.dec_priv_key = "11f0abdf4170f59ef4fca7871490f34902084ca84e299bedf0958401",
//QeCAVSx = 60aa94e6b899069c6711221a332d3156168537a085011efe054d4cdf
//QeCAVSy = 9ac019527cf4a7a4cd084856e80462f9fab7b8bd12b37d1b31bf03a5
.eph_priv_key = "0e6d170df9aeeeaf4c14f734745ac83bf44b4b2e2419c44cb9dba4d2",
//QsIUTx = 91ac459a13e4ee58306d02eb7cfb065d253ac0a07698dae19272c989
//QsIUTy = d68c441be99223d911fe8da0277c10378943bc03725af4b77d844516
.Z = "398b22a9a4c6da8f6677ef14994a057de60da78126bbd77e70e8e4e4",
//KDF(Z,0491ac459a13e4ee58306d02eb7cfb065d253ac0a07698dae19272c989d68c441be99223d911fe8da0277c10378943bc03725af4b77d844516
//    ) = c27836e8c57002dd0235a169261cba853df6168fe5d241fe40b053836368edba
.message = "f04e8860e6b86552cfa933c387",
// Key = c27836e8c57002dd0235a169261cba85
// IV = 3df6168fe5d241fe40b053836368edba
// Encrypted message = 8f0c245444ff400ce727bbf684
// Mac Tag = 4010ecd67692d61989a3c3ea67aad0a6
.cipher = "0491ac459a13e4ee58306d02eb7cfb065d253ac0a07698dae19272c989d68c441be99223d911fe8da0277c10378943bc03725af4b77d844516"
"8f0c245444ff400ce727bbf684"
"4010ecd67692d61989a3c3ea67aad0a6",
.compact_cipher = "91ac459a13e4ee58306d02eb7cfb065d253ac0a07698dae19272c989"
"355ad507a2c8a55064c3819d00"
"39b0417aa576af96726ef252076884a7",
.options=ECIES_EXPORT_PUB_STANDARD|ECIES_EPH_PUBKEY_AND_SHAREDINFO1,
.sharedInfo1="Test1",
.sharedInfo2="",
},
// P256, SHA256, no diversification
{
    .di=di_SHA256,
    .curve=&ccec_cp_256,
    .mac_nbytes = 16,
    .key_nbytes = 16,
	.dec_priv_key = "5abf13dbd59e0c5872bd9e72b4e17c5c9e6fe956b51aca389ad43ff5594c82b3",
	//QeCAVSx = 230951e9f774dae7c7938fcfe407a54981bda3b6b79bb37d82823f9b4ae065d5
	//QeCAVSy = 4b30c7314c1b96b0554e26e95d641408df645349a14090cd672ae9cc5829a3c4
	.eph_priv_key = "1ffe7e4cbbb59f069806ebbcd18f66bc42ac3cfc9b8d0d61c7a50e94f71cf6b5",
	//QsIUTx = 895ce51cabc5cc0f857504bc684106290335538298b9de9c4759a8b3945f451d
	//QsIUTy = aebf853151e56f3ed04b1e68bacb39c4c8e140c10cfca6e419478b07946abdab
	.Z = "fa17d1d5717a75202a3e02ea665322f3566407d631c93a06ba278ba68a2f2c45",
    //KDF(Z,00000001,"") = 6f2e784ff28f857a87d0601e9dc6a3ba0b5f4a9b667c44b1b270b65604b599a8
    .message = "f04e8860e6b86552cfa933c387",
    // Key = 6f2e784ff28f857a87d0601e9dc6a3ba
    // IV = 0b5f4a9b667c44b1b270b65604b599a8
    // Encrypted message = df7035d2f7e078978325d6ba6a
    // Mac Tag = 65db3b6acaba2a636a3f8a02b42f2517
    .cipher = "04895ce51cabc5cc0f857504bc684106290335538298b9de9c4759a8b3945f451daebf853151e56f3ed04b1e68bacb39c4c8e140c10cfca6e419478b07946abdab"
        "df7035d2f7e078978325d6ba6a"
        "65db3b6acaba2a636a3f8a02b42f2517",
    .compact_cipher = "895ce51cabc5cc0f857504bc684106290335538298b9de9c4759a8b3945f451d"
        "df7035d2f7e078978325d6ba6a"
        "65db3b6acaba2a636a3f8a02b42f2517",
    .options=ECIES_EXPORT_PUB_STANDARD,
    .sharedInfo1="",
    .sharedInfo2="",
},
// P256, SHA256, diversification SharedInfo 1 & 2
{
    .di=di_SHA256,
    .curve=&ccec_cp_256,
    .mac_nbytes = 16,
    .key_nbytes = 16,
	.dec_priv_key = "5abf13dbd59e0c5872bd9e72b4e17c5c9e6fe956b51aca389ad43ff5594c82b3",
	//QeCAVSx = 230951e9f774dae7c7938fcfe407a54981bda3b6b79bb37d82823f9b4ae065d5
	//QeCAVSy = 4b30c7314c1b96b0554e26e95d641408df645349a14090cd672ae9cc5829a3c4
	.eph_priv_key = "1ffe7e4cbbb59f069806ebbcd18f66bc42ac3cfc9b8d0d61c7a50e94f71cf6b5",
	//QsIUTx = 895ce51cabc5cc0f857504bc684106290335538298b9de9c4759a8b3945f451d
	//QsIUTy = aebf853151e56f3ed04b1e68bacb39c4c8e140c10cfca6e419478b07946abdab
	.Z = "fa17d1d5717a75202a3e02ea665322f3566407d631c93a06ba278ba68a2f2c45",
    //KDF(Z,00000001,"Test1") = 815a8e9607dc6d0dd3c7d7cafe931a9cfb332758a475d364e1567a8c50534ae8
    .message = "f04e8860e6b86552cfa933c387",
    // Key = 815a8e9607dc6d0dd3c7d7cafe931a9c
    // IV = fb332758a475d364e1567a8c50534ae8
    // Encrypted message = c0ec3c0e3733e7f258f99fef7a
    // Mac Tag = 63aee3667ce948ddad370bbe576b1a7a
    .cipher = "04895ce51cabc5cc0f857504bc684106290335538298b9de9c4759a8b3945f451daebf853151e56f3ed04b1e68bacb39c4c8e140c10cfca6e419478b07946abdab"
        "c0ec3c0e3733e7f258f99fef7a"
        "63aee3667ce948ddad370bbe576b1a7a",
    .compact_cipher = "895ce51cabc5cc0f857504bc684106290335538298b9de9c4759a8b3945f451d"
        "c0ec3c0e3733e7f258f99fef7a"
        "63aee3667ce948ddad370bbe576b1a7a",
    .options=ECIES_EXPORT_PUB_STANDARD,
    .sharedInfo1="Test1",
    .sharedInfo2="Test2",
},
// P256, SHA256, diversification SharedInfo 1 = Ephemeral public point
{
    .di=di_SHA256,
    .curve=&ccec_cp_256,
    .mac_nbytes = 16,
    .key_nbytes = 16,
	.dec_priv_key = "5abf13dbd59e0c5872bd9e72b4e17c5c9e6fe956b51aca389ad43ff5594c82b3",
	//QeCAVSx = 230951e9f774dae7c7938fcfe407a54981bda3b6b79bb37d82823f9b4ae065d5
	//QeCAVSy = 4b30c7314c1b96b0554e26e95d641408df645349a14090cd672ae9cc5829a3c4
	.eph_priv_key = "1ffe7e4cbbb59f069806ebbcd18f66bc42ac3cfc9b8d0d61c7a50e94f71cf6b5",
	//QsIUTx = 895ce51cabc5cc0f857504bc684106290335538298b9de9c4759a8b3945f451d
	//QsIUTy = aebf853151e56f3ed04b1e68bacb39c4c8e140c10cfca6e419478b07946abdab
	.Z = "fa17d1d5717a75202a3e02ea665322f3566407d631c93a06ba278ba68a2f2c45",
    //KDF(Z,04895ce51cabc5cc0f857504bc684106290335538298b9de9c4759a8b3945f451daebf853151e56f3ed04b1e68bacb39c4c8e140c10cfca6e419478b07946abdab
    //    ) = 864c47a851501ade4b749f1c4dbf02d4d1ec5aeac919571b84bde90d5480c11e
    .message = "f04e8860e6b86552cfa933c387",
    // Key = 864c47a851501ade4b749f1c4dbf02d4
    // IV = d1ec5aeac919571b84bde90d5480c11e
    // Encrypted message = 088d6bafa8f2f8cddb44b36840
    // Mac Tag = 609d6b24af270498d6f95a1b9d314c77
    .cipher = "04895ce51cabc5cc0f857504bc684106290335538298b9de9c4759a8b3945f451daebf853151e56f3ed04b1e68bacb39c4c8e140c10cfca6e419478b07946abdab"
        "088d6bafa8f2f8cddb44b36840"
        "609d6b24af270498d6f95a1b9d314c77",
    // Key = c392ed2d83ab68936c4dd22c19cbe5a1
    // IV = 3f8c1d25ba4d3348568e1166135686d5
    // Encrypted message = da7b95ebe064d5a59ae598417c
    // Mac Tag = 6ebd7c4a764f572826b49101f02a3e67
    .compact_cipher = "895ce51cabc5cc0f857504bc684106290335538298b9de9c4759a8b3945f451d"
        "da7b95ebe064d5a59ae598417c"
        "6ebd7c4a764f572826b49101f02a3e67",
    .options=ECIES_EXPORT_PUB_STANDARD|ECIES_EPH_PUBKEY_IN_SHAREDINFO1,
    .sharedInfo1="",
    .sharedInfo2="",
},
// P256, SHA256, diversification Ephemeral public point + SharedInfo 1
{
.di=di_SHA256,
.curve=&ccec_cp_256,
.mac_nbytes = 16,
.key_nbytes = 16,
.dec_priv_key = "5abf13dbd59e0c5872bd9e72b4e17c5c9e6fe956b51aca389ad43ff5594c82b3",
//QeCAVSx = 230951e9f774dae7c7938fcfe407a54981bda3b6b79bb37d82823f9b4ae065d5
//QeCAVSy = 4b30c7314c1b96b0554e26e95d641408df645349a14090cd672ae9cc5829a3c4
.eph_priv_key = "1ffe7e4cbbb59f069806ebbcd18f66bc42ac3cfc9b8d0d61c7a50e94f71cf6b5",
//QsIUTx = 895ce51cabc5cc0f857504bc684106290335538298b9de9c4759a8b3945f451d
//QsIUTy = aebf853151e56f3ed04b1e68bacb39c4c8e140c10cfca6e419478b07946abdab
.Z = "fa17d1d5717a75202a3e02ea665322f3566407d631c93a06ba278ba68a2f2c45",
//KDF(Z,04895ce51cabc5cc0f857504bc684106290335538298b9de9c4759a8b3945f451daebf853151e56f3ed04b1e68bacb39c4c8e140c10cfca6e419478b07946abdab
//    ) = 864c47a851501ade4b749f1c4dbf02d4d1ec5aeac919571b84bde90d5480c11e
.message = "f04e8860e6b86552cfa933c387",
// Key = 864c47a851501ade4b749f1c4dbf02d4
// IV = d1ec5aeac919571b84bde90d5480c11e
// Encrypted message = b275d3567020298ba58d19e62d
// Mac Tag = 719210a91f32c4ebad63e59dbc7e4c8c
.cipher = "04895ce51cabc5cc0f857504bc684106290335538298b9de9c4759a8b3945f451daebf853151e56f3ed04b1e68bacb39c4c8e140c10cfca6e419478b07946abdab"
"b275d3567020298ba58d19e62d"
"719210a91f32c4ebad63e59dbc7e4c8c",
// Key = c392ed2d83ab68936c4dd22c19cbe5a1
// IV = 3f8c1d25ba4d3348568e1166135686d5
// Encrypted message = 9cceae0a8ac9ca34efeffa4849
// Mac Tag = 95c674754a40aaf5edad47b87180a0be
.compact_cipher = "895ce51cabc5cc0f857504bc684106290335538298b9de9c4759a8b3945f451d"
"9cceae0a8ac9ca34efeffa4849"
"95c674754a40aaf5edad47b87180a0be",
.options=ECIES_EXPORT_PUB_STANDARD|ECIES_EPH_PUBKEY_AND_SHAREDINFO1,
.sharedInfo1="Test1",
.sharedInfo2="",
},
// P384, SHA384, no diversification
{
    .di=di_SHA384,
    .curve=&ccec_cp_384,
    .mac_nbytes = 16,
    .key_nbytes = 16,
    .dec_priv_key = "a826c4636474b208605393fdc4f664332ef8a3594474909f5e093738d893cc56431d223b1cd403d725e98058bbff9d02",
    //QeCAVSx = 81a5f71f204c3f4a96fe5aea9ceecfbedea8accf18925465bcb87b5fdb566079d4c909cb900efd2a7e6891bf91cc3afb
    //QeCAVSy = 82ae0a4b3b94445a5658326805a0501787f34249eb0ec63f1b06d0e05bc72e7888654f94af49cb425a8c1927bc4ad741
    .eph_priv_key = "00eb5222e7e73c887e45df9cf54b10e53a6a1ed8ab98a8363cd35fb0cdc5c05dee0642c71addaee88be7e81385f14060",
    //QsIUTx = 55c99300151be1c755058a125eb027ac188655bb7c002004541c74df24543066e7921e26f64d916476adddee04737d38
    //QsIUTy = 84b6258ec0079c4ac4e2efcd848ffc74fb2972a0228aed059549e04a9ab021dddf6d6fee19d7e5e4406bc49ad1023c20
    .Z = "deb56295d036ce1abe61070aba1435102665b911b64188a8ed9778c2ecf1606d51416d9370f5665f8525694753416e26",
    //KDF(Z,00000001,"") = 65073737cf26a082d57dad28f1f55aa01b65843662ee02c49dd6e10e3b57cb1b
    .message = "f04e8860e6b86552cfa933c387",
    // Key = 65073737cf26a082d57dad28f1f55aa0
    // IV = 1b65843662ee02c49dd6e10e3b57cb1b
    // Encrypted message = 773d869cf7deed8387e453921b
    // Mac Tag = 6536a76b5e09647efe74bf1779608241
    .cipher = "0455c99300151be1c755058a125eb027ac188655bb7c002004541c74df24543066e7921e26f64d916476adddee04737d3884b6258ec0079c4ac4e2efcd848ffc74fb2972a0228aed059549e04a9ab021dddf6d6fee19d7e5e4406bc49ad1023c20"
        "773d869cf7deed8387e453921b"
        "6536a76b5e09647efe74bf1779608241",
    .compact_cipher = "55c99300151be1c755058a125eb027ac188655bb7c002004541c74df24543066e7921e26f64d916476adddee04737d38"
        "773d869cf7deed8387e453921b"
        "6536a76b5e09647efe74bf1779608241",
    .options=ECIES_EXPORT_PUB_STANDARD,
    .sharedInfo1="",
    .sharedInfo2="",
},
// P384, SHA384, diversification SharedInfo 1 & 2
{
    .di=di_SHA384,
    .curve=&ccec_cp_384,
    .mac_nbytes = 16,
    .key_nbytes = 16,
    .dec_priv_key = "a826c4636474b208605393fdc4f664332ef8a3594474909f5e093738d893cc56431d223b1cd403d725e98058bbff9d02",
    //QeCAVSx = 81a5f71f204c3f4a96fe5aea9ceecfbedea8accf18925465bcb87b5fdb566079d4c909cb900efd2a7e6891bf91cc3afb
    //QeCAVSy = 82ae0a4b3b94445a5658326805a0501787f34249eb0ec63f1b06d0e05bc72e7888654f94af49cb425a8c1927bc4ad741
    .eph_priv_key = "00eb5222e7e73c887e45df9cf54b10e53a6a1ed8ab98a8363cd35fb0cdc5c05dee0642c71addaee88be7e81385f14060",
    //QsIUTx = 55c99300151be1c755058a125eb027ac188655bb7c002004541c74df24543066e7921e26f64d916476adddee04737d38
    //QsIUTy = 84b6258ec0079c4ac4e2efcd848ffc74fb2972a0228aed059549e04a9ab021dddf6d6fee19d7e5e4406bc49ad1023c20
    .Z = "deb56295d036ce1abe61070aba1435102665b911b64188a8ed9778c2ecf1606d51416d9370f5665f8525694753416e26",
    //KDF(Z,00000001,"Test1") = 4ebb4a7bd3be801f115083fa4991ba60fd47fdd4a523170f3b93b3fa42a4c1f2
    .message = "f04e8860e6b86552cfa933c387",
    // Key = 4ebb4a7bd3be801f115083fa4991ba60
    // IV = fd47fdd4a523170f3b93b3fa42a4c1f2
    // Encrypted message = 6f3f6e207332ac9f4590c849a8
    // Mac Tag = 6efc842ef9c6a5f17441e2152e04a0bb
    .cipher = "0455c99300151be1c755058a125eb027ac188655bb7c002004541c74df24543066e7921e26f64d916476adddee04737d3884b6258ec0079c4ac4e2efcd848ffc74fb2972a0228aed059549e04a9ab021dddf6d6fee19d7e5e4406bc49ad1023c20"
        "6f3f6e207332ac9f4590c849a8"
        "6efc842ef9c6a5f17441e2152e04a0bb",
    .compact_cipher = "55c99300151be1c755058a125eb027ac188655bb7c002004541c74df24543066e7921e26f64d916476adddee04737d38"
        "6f3f6e207332ac9f4590c849a8"
        "6efc842ef9c6a5f17441e2152e04a0bb",
    .options=ECIES_EXPORT_PUB_STANDARD,
    .sharedInfo1="Test1",
    .sharedInfo2="Test2",
},
// P384, SHA384, diversification SharedInfo 1 = Ephemeral public point
{
    .di=di_SHA384,
    .curve=&ccec_cp_384,
    .mac_nbytes = 12,
    .key_nbytes = 32,
    .dec_priv_key = "a826c4636474b208605393fdc4f664332ef8a3594474909f5e093738d893cc56431d223b1cd403d725e98058bbff9d02",
    //QeCAVSx = 81a5f71f204c3f4a96fe5aea9ceecfbedea8accf18925465bcb87b5fdb566079d4c909cb900efd2a7e6891bf91cc3afb
    //QeCAVSy = 82ae0a4b3b94445a5658326805a0501787f34249eb0ec63f1b06d0e05bc72e7888654f94af49cb425a8c1927bc4ad741
    .eph_priv_key = "00eb5222e7e73c887e45df9cf54b10e53a6a1ed8ab98a8363cd35fb0cdc5c05dee0642c71addaee88be7e81385f14060",
    //QsIUTx = 55c99300151be1c755058a125eb027ac188655bb7c002004541c74df24543066e7921e26f64d916476adddee04737d38
    //QsIUTy = 84b6258ec0079c4ac4e2efcd848ffc74fb2972a0228aed059549e04a9ab021dddf6d6fee19d7e5e4406bc49ad1023c20
    .Z = "deb56295d036ce1abe61070aba1435102665b911b64188a8ed9778c2ecf1606d51416d9370f5665f8525694753416e26",
    //KDF(Z,0455c99300151be1c755058a125eb027ac188655bb7c002004541c74df24543066e7921e26f64d916476adddee04737d3884b6258ec0079c4ac4e2efcd848ffc74fb2972a0228aed059549e04a9ab021dddf6d6fee19d7e5e4406bc49ad1023c20
    //    ) = 1324ab00fa742d67d16a497c3ac6e537befebb82cc248f5db9e40e47405bbbf5942cb7e635b156f3479c7e89d56f6b5c
    .message = "f04e8860e6b86552cfa933c387",
    // Key = 1324ab00fa742d67d16a497c3ac6e537befebb82cc248f5db9e40e47405bbbf5
    // IV = 942cb7e635b156f3479c7e89d56f6b5c
    // Encrypted message = 029c085010f037bbb7ad3c55bb
    // Mac Tag = dd61c712119981837db2d02d
    .cipher = "0455c99300151be1c755058a125eb027ac188655bb7c002004541c74df24543066e7921e26f64d916476adddee04737d3884b6258ec0079c4ac4e2efcd848ffc74fb2972a0228aed059549e04a9ab021dddf6d6fee19d7e5e4406bc49ad1023c20"
        "029c085010f037bbb7ad3c55bb"
        "dd61c712119981837db2d02d",
    // Key = 694a168ea6a225037e987940d7e3980ee986b4e21accdf2692c1bc8a6ad57749
    // IV = 3bbbdc9794c7d1e10e9be5d0a4fad08b
    // Encrypted message = 9ec1e94b105f31ad537ea5db8d
    // Mac Tag = 125e582f0ccb5cab78b34914
    .compact_cipher =   "55c99300151be1c755058a125eb027ac188655bb7c002004541c74df24543066e7921e26f64d916476adddee04737d38"
        "9ec1e94b105f31ad537ea5db8d"
        "125e582f0ccb5cab78b34914",
    .options=ECIES_EXPORT_PUB_STANDARD|ECIES_EPH_PUBKEY_IN_SHAREDINFO1,
    .sharedInfo1="",
    .sharedInfo2="",
},
// P384, SHA384, diversification Ephemeral public point + SharedInfo 1
{
.di=di_SHA384,
.curve=&ccec_cp_384,
.mac_nbytes = 12,
.key_nbytes = 32,
.dec_priv_key = "a826c4636474b208605393fdc4f664332ef8a3594474909f5e093738d893cc56431d223b1cd403d725e98058bbff9d02",
//QeCAVSx = 81a5f71f204c3f4a96fe5aea9ceecfbedea8accf18925465bcb87b5fdb566079d4c909cb900efd2a7e6891bf91cc3afb
//QeCAVSy = 82ae0a4b3b94445a5658326805a0501787f34249eb0ec63f1b06d0e05bc72e7888654f94af49cb425a8c1927bc4ad741
.eph_priv_key = "00eb5222e7e73c887e45df9cf54b10e53a6a1ed8ab98a8363cd35fb0cdc5c05dee0642c71addaee88be7e81385f14060",
//QsIUTx = 55c99300151be1c755058a125eb027ac188655bb7c002004541c74df24543066e7921e26f64d916476adddee04737d38
//QsIUTy = 84b6258ec0079c4ac4e2efcd848ffc74fb2972a0228aed059549e04a9ab021dddf6d6fee19d7e5e4406bc49ad1023c20
.Z = "deb56295d036ce1abe61070aba1435102665b911b64188a8ed9778c2ecf1606d51416d9370f5665f8525694753416e26",
//KDF(Z,0455c99300151be1c755058a125eb027ac188655bb7c002004541c74df24543066e7921e26f64d916476adddee04737d3884b6258ec0079c4ac4e2efcd848ffc74fb2972a0228aed059549e04a9ab021dddf6d6fee19d7e5e4406bc49ad1023c20
//    ) = 1324ab00fa742d67d16a497c3ac6e537befebb82cc248f5db9e40e47405bbbf5942cb7e635b156f3479c7e89d56f6b5c
.message = "f04e8860e6b86552cfa933c387",
// Key = 1324ab00fa742d67d16a497c3ac6e537befebb82cc248f5db9e40e47405bbbf5
// IV = 942cb7e635b156f3479c7e89d56f6b5c
// Encrypted message = 2f52f34e55de3b77c2bfa1939d
// Mac Tag = 51d43679b0130b14b8d584c2
.cipher = "0455c99300151be1c755058a125eb027ac188655bb7c002004541c74df24543066e7921e26f64d916476adddee04737d3884b6258ec0079c4ac4e2efcd848ffc74fb2972a0228aed059549e04a9ab021dddf6d6fee19d7e5e4406bc49ad1023c20"
"2f52f34e55de3b77c2bfa1939d"
"51d43679b0130b14b8d584c2",
// Key = 694a168ea6a225037e987940d7e3980ee986b4e21accdf2692c1bc8a6ad57749
// IV = 3bbbdc9794c7d1e10e9be5d0a4fad08b
// Encrypted message = 99cc7a3369c068c714d4866fd3
// Mac Tag = f87bc55759278dcd95a691d9
.compact_cipher =   "55c99300151be1c755058a125eb027ac188655bb7c002004541c74df24543066e7921e26f64d916476adddee04737d38"
"99cc7a3369c068c714d4866fd3"
"f87bc55759278dcd95a691d9",
.options=ECIES_EXPORT_PUB_STANDARD|ECIES_EPH_PUBKEY_AND_SHAREDINFO1,
.sharedInfo1="Test1",
.sharedInfo2="",
},
// P521, SHA512, no diversification
{
    .di=di_SHA512,
    .curve=&ccec_cp_521,
    .mac_nbytes = 16,
    .key_nbytes = 16,
    .dec_priv_key = "000000ccf9c2481d36c1a7a9ad516a63e60871c43e74fe6392409ac5e939dff933df5b6edfcae04966ee5e8da8f7c3232572a084a84b2a1db370d93729b70ebd822cc35a",
    //QeCAVSx = 000001e12f3e23bdd037d7e607cdc7253c99434b290189b7ebe29c04e568aae2d43aee68449f7bc59363cfa8d295d712428af93113eb7c6a50444a0881725997200c36f3
    //QeCAVSy = 000000bdb19d1c7a9aee4819e1a1a4358c285242acdba2bd4edf627c905ba33e33557cd2f12cbf444cef49ba679ab5c7e8590bf05969c5fb52df6d5b88e8984ea261185a
    .eph_priv_key = "000000ea3f82bf7c3d8a762a5b8ef1031d4c477ed9023a2a4671139b58066fbb393343fd68451c768a6ac8e5756409fd6fce0064aa27f8b345831f80e3ff9360171f682d",
    //QsIUTx = 000000d5baed4fd07eb677c3ceaf14543a4797305a68c3235ff1df538da35a9b4eb0a7c4392640b87b2cf9924e525290535e17d6e3517b5a21486bdea96afe3d3f8eae57
    //QsIUTy = 000000880a741d94a068e9b8e9b979bdcccc5ccf10fc768115d2db635b531e84374d4872d423f6fd43fca25f3c881387fb19f4376e328024341c8ecac77335748c90e76b
    .Z = "005b63293248ef5ebe1852be8f6bdcc8a679b293928c3586fc53dc7c1cf69fa760987a40044f7dba38f8c08e2566e24e7b8e9dc3080b95fa3dbe549eb1aaa0665d4b",
    //KDF(Z,00000001,"") = 140741425a7e0c2e8b96df45fe64ca086de4e7b5876dfce8cbff0cb4216accba
    .message = "f04e8860e6b86552cfa933c387",
    // Key = 140741425a7e0c2e8b96df45fe64ca08
    // IV = 6de4e7b5876dfce8cbff0cb4216accba
    // Encrypted message = ed828f73636d8cea7bafda7e11
    // Mac Tag = df8ee19be4dd55a10c8a98d17c465573
    .cipher = "0400d5baed4fd07eb677c3ceaf14543a4797305a68c3235ff1df538da35a9b4eb0a7c4392640b87b2cf9924e525290535e17d6e3517b5a21486bdea96afe3d3f8eae5700880a741d94a068e9b8e9b979bdcccc5ccf10fc768115d2db635b531e84374d4872d423f6fd43fca25f3c881387fb19f4376e328024341c8ecac77335748c90e76b"
        "ed828f73636d8cea7bafda7e11"
        "df8ee19be4dd55a10c8a98d17c465573",
    .compact_cipher = "00d5baed4fd07eb677c3ceaf14543a4797305a68c3235ff1df538da35a9b4eb0a7c4392640b87b2cf9924e525290535e17d6e3517b5a21486bdea96afe3d3f8eae57"
        "ed828f73636d8cea7bafda7e11"
        "df8ee19be4dd55a10c8a98d17c465573",
    .options=ECIES_EXPORT_PUB_STANDARD,
    .sharedInfo1="",
    .sharedInfo2="",
},
// P521, SHA512, diversification SharedInfo 1 & 2
{
    .di=di_SHA512,
    .curve=&ccec_cp_521,
    .mac_nbytes = 16,
    .key_nbytes = 24,
    .dec_priv_key = "000000ccf9c2481d36c1a7a9ad516a63e60871c43e74fe6392409ac5e939dff933df5b6edfcae04966ee5e8da8f7c3232572a084a84b2a1db370d93729b70ebd822cc35a",
    //QeCAVSx = 000001e12f3e23bdd037d7e607cdc7253c99434b290189b7ebe29c04e568aae2d43aee68449f7bc59363cfa8d295d712428af93113eb7c6a50444a0881725997200c36f3
    //QeCAVSy = 000000bdb19d1c7a9aee4819e1a1a4358c285242acdba2bd4edf627c905ba33e33557cd2f12cbf444cef49ba679ab5c7e8590bf05969c5fb52df6d5b88e8984ea261185a
    .eph_priv_key = "000000ea3f82bf7c3d8a762a5b8ef1031d4c477ed9023a2a4671139b58066fbb393343fd68451c768a6ac8e5756409fd6fce0064aa27f8b345831f80e3ff9360171f682d",
    //QsIUTx = 000000d5baed4fd07eb677c3ceaf14543a4797305a68c3235ff1df538da35a9b4eb0a7c4392640b87b2cf9924e525290535e17d6e3517b5a21486bdea96afe3d3f8eae57
    //QsIUTy = 000000880a741d94a068e9b8e9b979bdcccc5ccf10fc768115d2db635b531e84374d4872d423f6fd43fca25f3c881387fb19f4376e328024341c8ecac77335748c90e76b
    .Z = "005b63293248ef5ebe1852be8f6bdcc8a679b293928c3586fc53dc7c1cf69fa760987a40044f7dba38f8c08e2566e24e7b8e9dc3080b95fa3dbe549eb1aaa0665d4b",
    //KDF(Z,00000001,"Test1") = baaf86745769c7291cf6f88df9800972263f59d6246e5429ae3ceeef07067c26efde3e82b35e3354
    .message = "f04e8860e6b86552cfa933c387",
    // Key = baaf86745769c7291cf6f88df9800972263f59d6246e5429
    // IV = ae3ceeef07067c26efde3e82b35e3354
    // Encrypted message = 76ff36ef4fbbe1083f7dc41018
    // Mac Tag = 2cb5ced9a6e72bc500ced8db40c6d4fe
    .cipher = "0400d5baed4fd07eb677c3ceaf14543a4797305a68c3235ff1df538da35a9b4eb0a7c4392640b87b2cf9924e525290535e17d6e3517b5a21486bdea96afe3d3f8eae5700880a741d94a068e9b8e9b979bdcccc5ccf10fc768115d2db635b531e84374d4872d423f6fd43fca25f3c881387fb19f4376e328024341c8ecac77335748c90e76b"
        "76ff36ef4fbbe1083f7dc41018"
        "2cb5ced9a6e72bc500ced8db40c6d4fe",
    .compact_cipher =
"00d5baed4fd07eb677c3ceaf14543a4797305a68c3235ff1df538da35a9b4eb0a7c4392640b87b2cf9924e525290535e17d6e3517b5a21486bdea96afe3d3f8eae57"
        "76ff36ef4fbbe1083f7dc41018"
        "2cb5ced9a6e72bc500ced8db40c6d4fe",
    .options=ECIES_EXPORT_PUB_STANDARD,
    .sharedInfo1="Test1",
    .sharedInfo2="Test2",
},
// P521, SHA512, diversification SharedInfo 1 = Ephemeral public point
{
    .di=di_SHA512,
    .curve=&ccec_cp_521,
    .mac_nbytes = 12,
    .key_nbytes = 32,
    .dec_priv_key = "000000ccf9c2481d36c1a7a9ad516a63e60871c43e74fe6392409ac5e939dff933df5b6edfcae04966ee5e8da8f7c3232572a084a84b2a1db370d93729b70ebd822cc35a",
    //QeCAVSx = 000001e12f3e23bdd037d7e607cdc7253c99434b290189b7ebe29c04e568aae2d43aee68449f7bc59363cfa8d295d712428af93113eb7c6a50444a0881725997200c36f3
    //QeCAVSy = 000000bdb19d1c7a9aee4819e1a1a4358c285242acdba2bd4edf627c905ba33e33557cd2f12cbf444cef49ba679ab5c7e8590bf05969c5fb52df6d5b88e8984ea261185a
    .eph_priv_key = "000000ea3f82bf7c3d8a762a5b8ef1031d4c477ed9023a2a4671139b58066fbb393343fd68451c768a6ac8e5756409fd6fce0064aa27f8b345831f80e3ff9360171f682d",
    //QsIUTx = 000000d5baed4fd07eb677c3ceaf14543a4797305a68c3235ff1df538da35a9b4eb0a7c4392640b87b2cf9924e525290535e17d6e3517b5a21486bdea96afe3d3f8eae57
    //QsIUTy = 000000880a741d94a068e9b8e9b979bdcccc5ccf10fc768115d2db635b531e84374d4872d423f6fd43fca25f3c881387fb19f4376e328024341c8ecac77335748c90e76b
    .Z = "005b63293248ef5ebe1852be8f6bdcc8a679b293928c3586fc53dc7c1cf69fa760987a40044f7dba38f8c08e2566e24e7b8e9dc3080b95fa3dbe549eb1aaa0665d4b",
    //KDF(Z,0400d5baed4fd07eb677c3ceaf14543a4797305a68c3235ff1df538da35a9b4eb0a7c4392640b87b2cf9924e525290535e17d6e3517b5a21486bdea96afe3d3f8eae5700880a741d94a068e9b8e9b979bdcccc5ccf10fc768115d2db635b531e84374d4872d423f6fd43fca25f3c881387fb19f4376e328024341c8ecac77335748c90e76b
    //    ) = d4c84d7a57a957c689160b153e98041e3f81e4af9b6d72cdc877448f5e1424a554ca7410b1424761831470d3df8141c7
    .message = "f04e8860e6b86552cfa933c387",
    // Key = d4c84d7a57a957c689160b153e98041e3f81e4af9b6d72cdc877448f5e1424a5
    // IV = 54ca7410b1424761831470d3df8141c7
    // Encrypted message = 8da729a367662464eacda845cd
    // Mac Tag = e9d61114f45f6b4cc6a5e618
    .cipher = "0400d5baed4fd07eb677c3ceaf14543a4797305a68c3235ff1df538da35a9b4eb0a7c4392640b87b2cf9924e525290535e17d6e3517b5a21486bdea96afe3d3f8eae5700880a741d94a068e9b8e9b979bdcccc5ccf10fc768115d2db635b531e84374d4872d423f6fd43fca25f3c881387fb19f4376e328024341c8ecac77335748c90e76b"
        "8da729a367662464eacda845cd"
        "e9d61114f45f6b4cc6a5e618",
    // Key = acd5b7dacf19617b3b9bc4a95b1d693cb8998177940dd972374b16e5570bea62
    // IV = 58a83d6efb0f82770ef53323b9221431
    // Encrypted message = 311f38f9c2a4e519caaba613b3
    // Mac Tag = c4a23c6be2f16f83301aa1dc
    .compact_cipher ="00d5baed4fd07eb677c3ceaf14543a4797305a68c3235ff1df538da35a9b4eb0a7c4392640b87b2cf9924e525290535e17d6e3517b5a21486bdea96afe3d3f8eae57"
        "311f38f9c2a4e519caaba613b3"
        "c4a23c6be2f16f83301aa1dc",

    .options=ECIES_EXPORT_PUB_STANDARD|ECIES_EPH_PUBKEY_IN_SHAREDINFO1,
    .sharedInfo1="",
    .sharedInfo2="",
},
// P521, SHA512, diversification Ephemeral public point + SharedInfo 1
{
.di=di_SHA512,
.curve=&ccec_cp_521,
.mac_nbytes = 12,
.key_nbytes = 32,
.dec_priv_key = "000000ccf9c2481d36c1a7a9ad516a63e60871c43e74fe6392409ac5e939dff933df5b6edfcae04966ee5e8da8f7c3232572a084a84b2a1db370d93729b70ebd822cc35a",
//QeCAVSx = 000001e12f3e23bdd037d7e607cdc7253c99434b290189b7ebe29c04e568aae2d43aee68449f7bc59363cfa8d295d712428af93113eb7c6a50444a0881725997200c36f3
//QeCAVSy = 000000bdb19d1c7a9aee4819e1a1a4358c285242acdba2bd4edf627c905ba33e33557cd2f12cbf444cef49ba679ab5c7e8590bf05969c5fb52df6d5b88e8984ea261185a
.eph_priv_key = "000000ea3f82bf7c3d8a762a5b8ef1031d4c477ed9023a2a4671139b58066fbb393343fd68451c768a6ac8e5756409fd6fce0064aa27f8b345831f80e3ff9360171f682d",
//QsIUTx = 000000d5baed4fd07eb677c3ceaf14543a4797305a68c3235ff1df538da35a9b4eb0a7c4392640b87b2cf9924e525290535e17d6e3517b5a21486bdea96afe3d3f8eae57
//QsIUTy = 000000880a741d94a068e9b8e9b979bdcccc5ccf10fc768115d2db635b531e84374d4872d423f6fd43fca25f3c881387fb19f4376e328024341c8ecac77335748c90e76b
.Z = "005b63293248ef5ebe1852be8f6bdcc8a679b293928c3586fc53dc7c1cf69fa760987a40044f7dba38f8c08e2566e24e7b8e9dc3080b95fa3dbe549eb1aaa0665d4b",
//KDF(Z,0400d5baed4fd07eb677c3ceaf14543a4797305a68c3235ff1df538da35a9b4eb0a7c4392640b87b2cf9924e525290535e17d6e3517b5a21486bdea96afe3d3f8eae5700880a741d94a068e9b8e9b979bdcccc5ccf10fc768115d2db635b531e84374d4872d423f6fd43fca25f3c881387fb19f4376e328024341c8ecac77335748c90e76b
//    ) = d4c84d7a57a957c689160b153e98041e3f81e4af9b6d72cdc877448f5e1424a554ca7410b1424761831470d3df8141c7
.message = "f04e8860e6b86552cfa933c387",
// Key = d4c84d7a57a957c689160b153e98041e3f81e4af9b6d72cdc877448f5e1424a5
// IV = 54ca7410b1424761831470d3df8141c7
// Encrypted message = 4d0cade27eca77a773a737e472
// Mac Tag = 6fa72b0dde4594e5b2536192
.cipher = "0400d5baed4fd07eb677c3ceaf14543a4797305a68c3235ff1df538da35a9b4eb0a7c4392640b87b2cf9924e525290535e17d6e3517b5a21486bdea96afe3d3f8eae5700880a741d94a068e9b8e9b979bdcccc5ccf10fc768115d2db635b531e84374d4872d423f6fd43fca25f3c881387fb19f4376e328024341c8ecac77335748c90e76b"
"4d0cade27eca77a773a737e472"
"6fa72b0dde4594e5b2536192",
// Key = acd5b7dacf19617b3b9bc4a95b1d693cb8998177940dd972374b16e5570bea62
// IV = 58a83d6efb0f82770ef53323b9221431
// Encrypted message = 37ec0b2dd001ed0489ca99a82f
// Mac Tag = 85b074e42c7b73a626b0e320
.compact_cipher ="00d5baed4fd07eb677c3ceaf14543a4797305a68c3235ff1df538da35a9b4eb0a7c4392640b87b2cf9924e525290535e17d6e3517b5a21486bdea96afe3d3f8eae57"
"37ec0b2dd001ed0489ca99a82f"
"85b074e42c7b73a626b0e320",

.options=ECIES_EXPORT_PUB_STANDARD|ECIES_EPH_PUBKEY_AND_SHAREDINFO1,
.sharedInfo1="Test1",
.sharedInfo2="",
},
