/* Copyright (c) (2015,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

//these test vectors are from openssl
/*
ccsymmetric_test_vector aes_gcm_vectors[]={
*/  
    {
        .keyStr="00000000000000000000000000000000",
        .ptStr="",
        .aDataStr="",
        .init_ivStr="000000000000000000000000",
        .ctStr="",
        .tagStr="58e2fccefa7e3061367f1d57a4e7455a",
    },
    {
        .keyStr="00000000000000000000000000000000",
        .ptStr="00000000000000000000000000000000",
        .aDataStr="",
        .init_ivStr="000000000000000000000000",
        .ctStr="0388dace60b6a392f328c2b971b2fe78",
        .tagStr="ab6e47d42cec13bdf53a67b21257bddf",
    },
    {
        .keyStr="feffe9928665731c6d6a8f9467308308",
        .ptStr="d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        .aDataStr="",
        .init_ivStr="cafebabefacedbaddecaf888",
        .ctStr="42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
        .tagStr="4d5c2af327cd64a62cf35abd2ba6fab4",
    },
    {
        .keyStr="feffe9928665731c6d6a8f9467308308",
        .ptStr="d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        .aDataStr= "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        .init_ivStr="cafebabefacedbaddecaf888",
        .ctStr="42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        .tagStr="5bc94fbc3221a5db94fae95ae7121a47",
    },
    {
        .keyStr="feffe9928665731c6d6a8f9467308308",
        .ptStr="d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        .aDataStr="feedfacedeadbeeffeedfacedeadbeefabaddad2",
        .init_ivStr="cafebabefacedbad",
        .ctStr="61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
        .tagStr="3612d2e79e3b0785561be14aaca2fccb",
    },
    {
        .keyStr= "feffe9928665731c6d6a8f9467308308",
        .ptStr="d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        .aDataStr="feedfacedeadbeeffeedfacedeadbeefabaddad2",
        .init_ivStr="9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
        .ctStr="8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5",
        .tagStr="619cc5aefffe0bfa462af43c1699d050",
    },
    {
        .keyStr= "000000000000000000000000000000000000000000000000",
        .ptStr="",
        .aDataStr= "",
        .init_ivStr="000000000000000000000000",
        .ctStr= "",
        .tagStr="cd33b28ac773f74ba00ed1f312572435",
    },
    {
        .keyStr="000000000000000000000000000000000000000000000000",
        .ptStr="00000000000000000000000000000000",
        .aDataStr="",
        .init_ivStr="000000000000000000000000",
        .ctStr="98e7247c07f0fe411c267e4384b0f600",
        .tagStr="2ff58d80033927ab8ef4d4587514f0fb",
    },
    {
        .keyStr="feffe9928665731c6d6a8f9467308308feffe9928665731c",
        .ptStr="d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        .aDataStr="",
        .init_ivStr="cafebabefacedbaddecaf888",
        .ctStr="3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256",
        .tagStr="9924a7c8587336bfb118024db8674a14",
    },
    {
       .keyStr= "feffe9928665731c6d6a8f9467308308feffe9928665731c",
        .ptStr="d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        .aDataStr="feedfacedeadbeeffeedfacedeadbeefabaddad2",
        .init_ivStr="cafebabefacedbaddecaf888",
        .ctStr="3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710",
        .tagStr="2519498e80f1478f37ba55bd6d27618c",
    },
    {
        .keyStr="feffe9928665731c6d6a8f9467308308feffe9928665731c",
        .ptStr="d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        .aDataStr="feedfacedeadbeeffeedfacedeadbeefabaddad2",
        .init_ivStr="cafebabefacedbad",
        .ctStr="0f10f599ae14a154ed24b36e25324db8c566632ef2bbb34f8347280fc4507057fddc29df9a471f75c66541d4d4dad1c9e93a19a58e8b473fa0f062f7",
        .tagStr="65dcc57fcf623a24094fcca40d3533f8",
    },
    {
        .keyStr="feffe9928665731c6d6a8f9467308308feffe9928665731c",
        .ptStr="d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        .aDataStr="feedfacedeadbeeffeedfacedeadbeefabaddad2",
        .init_ivStr="cafebabefacedbad",
        .ctStr="0f10f599ae14a154ed24b36e25324db8c566632ef2bbb34f8347280fc4507057fddc29df9a471f75c66541d4d4dad1c9e93a19a58e8b473fa0f062f7",
        .tagStr="65dcc57fcf623a24094fcca40d3533f8",
    },
    {
        .keyStr= "feffe9928665731c6d6a8f9467308308feffe9928665731c",
        .ptStr= "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        .aDataStr= "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        .init_ivStr= "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
        .ctStr="d27e88681ce3243c4830165a8fdcf9ff1de9a1d8e6b447ef6ef7b79828666e4581e79012af34ddd9e2f037589b292db3e67c036745fa22e7e9b7373b",
        .tagStr="dcf566ff291c25bbb8568fc3d376a6d9",
    },
    {
        .keyStr= "0000000000000000000000000000000000000000000000000000000000000000",
        .ptStr="",
        .aDataStr= "",
        .init_ivStr="000000000000000000000000",
        .ctStr="",
        .tagStr="530f8afbc74536b9a963b4f1c4cb738b",
    },
    {
        .keyStr="0000000000000000000000000000000000000000000000000000000000000000",
        .ptStr= "00000000000000000000000000000000",
        .aDataStr= "",
        .init_ivStr="000000000000000000000000",
        .ctStr="cea7403d4d606b6e074ec5d3baf39d18",
        .tagStr="d0d1c8a799996bf0265b98b5d48ab919",
    },
    {
        .keyStr= "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        .ptStr="d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        .aDataStr= "",
        .init_ivStr="cafebabefacedbaddecaf888",
        .ctStr="522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
        .tagStr="b094dac5d93471bdec1a502270e3cc6c",
    },
    {
        .keyStr="feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        .ptStr="d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        .aDataStr="feedfacedeadbeeffeedfacedeadbeefabaddad2",
        .init_ivStr="cafebabefacedbaddecaf888",
        .ctStr="522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        .tagStr="76fc6ece0f4e1768cddf8853bb2d551b",
    },
    {
        .keyStr= "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        .ptStr="d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        .aDataStr= "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        .init_ivStr="cafebabefacedbad",
        .ctStr="c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f",
        .tagStr="3a337dbf46a792c45e454913fe2ea8f2",
    },
    {
        .keyStr="feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        .ptStr="d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        .aDataStr="feedfacedeadbeeffeedfacedeadbeefabaddad2",
        .init_ivStr="9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
        .ctStr="5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f",
        .tagStr="a44a8266ee1c8eb0c8b5d4cf5ae9f19a",
    },
    {
        .keyStr="00000000000000000000000000000000",
        .ptStr="",
        .aDataStr="d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
        .init_ivStr="000000000000000000000000",
        .ctStr="",
        .tagStr="5fea793a2d6f974d37e68e0cb8ff9492",
    },
    {
        .keyStr="00000000000000000000000000000000",
        .ptStr="000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        .aDataStr="",
        /* This nonce results in 0xfff in counter LSB. */
        .init_ivStr="ffffffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        .ctStr="56b3373ca9ef6e4a2b64fe1e9a17b61425f10d47a75a5fce13efc6bc784af24f4141bdd48cf7c770887afd573cca5418a9aeffcd7c5ceddfc6a78397b9a85b499da558257267caab2ad0b23ca476a53cb17fb41c4b8b475cb4f3f7165094c229c9e8c4dc0a2a5ff1903e501511221376a1cdb8364c5061a20cae74bc4acd76ceb0abc9fd3217ef9f8c90be402ddf6d8697f4f880dff15bfb7a6b28241ec8fe183c2d59e3f9dfff653c7126f0acb9e64211f42bae12af462b1070bef1ab5e3606872ca10dee15b3249b1a1b958f23134c4bccb7d03200bce420a2f8eb66dcf3644d1423c1b5699003c13ecef4bf38a3b60eedc34033bac1902783dc6d89e2e774188a439c7ebcc0672dbda4ddcfb2794613b0be41315ef778708a70ee7d75165c",
        .tagStr="8b307f6b33286d0ab026a9ed3fe1e85f",
    },



