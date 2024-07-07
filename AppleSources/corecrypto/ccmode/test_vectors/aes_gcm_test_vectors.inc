/* Copyright (c) (2015,2017,2019,2020) Apple Inc. All rights reserved.
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
ccsymmetric_test_vector aes_gcm_vectors[]={
{

*/
   {
        .keyStr="c0ba351e59a21397e7b8ed7cab5a06f670ed3ecba7e58ace1742446851447cd2",
        .aDataStr="",
        .init_ivStr="99fbfc5106a564cf425d64a46d068327",
        .ptStr="f04e8860e6b86552cfa933c387",
        .ctStr="f9ad905b1c77148c5dbc8d596e",
        .tagStr="6b30f1a60cfdc31bf8c4e7db5258fd94"
    },{
        .keyStr="E3C08A8F06C6E3AD95A70557B23F75483CE33021A9C72B7025666204C69C0B72",
        .ptStr="",
        .aDataStr=
        "D609B1F056637A0D46DF998D88E5222A"
        "B2C2846512153524C0895E8108000F10"
        "1112131415161718191A1B1C1D1E1F20"
        "2122232425262728292A2B2C2D2E2F30"
        "313233340001",
        .init_ivStr="12153524C0895E81B2C28465",
        .ctStr="",
        .tagStr="2F0BC5AF409E06D609EA8B7D0FA5EA50",
    },{
        .keyStr="feffe9928665731c6d6a8f9467308308",
        .aDataStr="",
        .init_ivStr="cafebabefacedbaddecaf888",
        .ptStr="d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        .ctStr="42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
        .tagStr="4d5c2af327cd64a62cf35abd2ba6fab4",
    },{
        .keyStr="feffe9928665731c6d6a8f9467308308",
        .aDataStr="feedfacedeadbeeffeedfacedeadbeefabaddad2",
        .init_ivStr="cafebabefacedbaddecaf888",
        .ptStr="d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        .ctStr="42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        .tagStr="5bc94fbc3221a5db94fae95ae7121a47",
    },{
        .keyStr="feffe9928665731c6d6a8f9467308308",
        .aDataStr="feedfacedeadbeeffeedfacedeadbeefabaddad2",
        .init_ivStr="cafebabefacedbad",
        .ptStr="d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        .ctStr="61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
        .tagStr="3612d2e79e3b0785561be14aaca2fccb",
    },{
        .keyStr="feffe9928665731c6d6a8f9467308308",
        .aDataStr="feedfacedeadbeeffeedfacedeadbeefabaddad2",
        .init_ivStr="9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
        .ptStr="d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        .ctStr="8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5",
        .tagStr="619cc5aefffe0bfa462af43c1699d050",
    },{
        .keyStr="00000000000000000000000000000000",
        .aDataStr="688e1aa984de926dc7b4c47f44",
        .init_ivStr="b72138b5a05ff5070e8cd94183f761d8",
        .ptStr="a2aab3ad8b17acdda288426cd7c429b7ca86b7aca05809c70ce82db25711cb5302eb2743b036f3d750d6cf0dc0acb92950d546db308f93b4ff244afa9dc72bcd758d2c",
        .ctStr="cbc8d2f15481a4cc7dd1e19aaa83de5678483ec359ae7dec2ab8d534e0906f4b4663faff58a8b2d733b845eef7c9b331e9e10eb2612c995feb1ac15a6286cce8b297a8",
        .tagStr="8d2d2a9372626f6bee8580276a6366bf",
    },{
        .keyStr="00000000000000000000000000000000",
        .aDataStr="",
        .init_ivStr="000000000000000000000000",
        .ptStr="",
        .ctStr="",
        .tagStr="58e2fccefa7e3061367f1d57a4e7455a",
    },{
        .keyStr ="0e5d6e68f82f32bea3f0b69498c1a31ef6d955cd3d27a2a8",
        .aDataStr ="",
        .init_ivStr = "caf72ee1e62e1001e8cfbc63",
        .ptStr ="",
        .ctStr ="",
        .tagStr = "db1a74ffb5f7de26f5742e0942b1b9cb",
    },{
        .keyStr = "0e5d6e68f82f32bea3f0b69498c1a31ef6d955cd3d27a2a8",
        .init_ivStr = "caf72ee1e62e1001e8cfbc63",
        .ctStr ="",
        .aDataStr="",
        .tagStr = "db1a74ffb5f7de26f5742e0942b1b9cb",
        .ptStr="",
    },{
        .keyStr = "0ed9f074d53b9b71bb87d123c16d269728ad819d89bba91c",
        .init_ivStr = "8b4e5be3cef24b12640bd781",
        .ctStr ="",
        .aDataStr ="",
        .tagStr = "258e9d80875b4a6f4b7216da0db35e47",
        .ptStr =""
    },{
        .keyStr = "6e50fcc4b69e9623f6d55849c14434be8a1d38f910f38315300a3ca3cb71c7d5",
        .init_ivStr = "b6e85801abd072db8852514c",
        .ptStr = "e99904b921168e0ba6a5ccef33",
        .aDataStr = "a1fa6bf9f7527cc405310e0cf2c63b84dd4fef93b20214d00390260aa44bc7f39536777e8ac69e33b8b7b69b4fd81af2d817bfcc8f6f8aabcf748fc7e9feb6757d21899c78d8a134a55b90eaa9e895b31a9fb4d37daa84bc8642",
        .ctStr = "5b0ea5d1167131929f74299a5f",
        .tagStr = "22235511743d0b83ae5ab76d9fa315",
    },{
        .keyStr = "260be169d5569c560880b762da9010e8d5e90900d6c96135ada7ff201d94f1b0",
        .init_ivStr = "49991601527beb72c4d09e24",
        .ptStr = "392770991e4cfff294fc67ab0f",
        .aDataStr = "0c25cc102fc321d6c46a66349cbf649435f1118d1d1e7c1d9aac79c5488a334c1b5ea375b43d382338fa2fab7d02caf45d2e923f565699fb11adfaa91fc929a8cf8a3600351697f30c205f7a9306d2806c540a0412e8e5f6cfec",
        .ctStr = "01a0fdba4247aee50e5161b3a4",
        .tagStr = "4a239ba53bd66a1071bfb1c58f9949",
    },{
        .keyStr = "3136ade375dfe36d7f6ac8da6edeec6bebe3cb76125035d4a872af6ba949b991",
        .init_ivStr = "b6",
        .ctStr = "6de100dd5b39fc896c465cb5ab0d785acec36512774b737ad828fd635cc3f27c",
        .aDataStr = "57985a8044bb3e95391d560ecd3fdbe7",
        .tagStr = "2de13adfc755488e2e04922c1b",
        .ptStr = "68fc9163e78144d2208d72a9649d8d547dc3ee4ab8ace74807c842d71142efaf",

    },{
        .keyStr = "7f6319ffa664935e64f2047a03cc21e1b2c6c98b25d9b0b62f0873d1482aa786",
        .init_ivStr = "68",
        .ctStr = "e9e845418bd2283c79041c31dcf4027a6ce962f77c59c00a35a2adc2b9f6eb8fd3faefd516b813eabca65f7df8dd854f2a366b",
        .aDataStr = "7d30d9f9914725c2c8f9222a08fc99a6c7647a4bb1d1587d13dbedae470581c4a4df72af1dd4b1c520571439da3e0763",
        .tagStr = "89fb3fa11951efd46e85ecfea5e9",
        .ptStr = "ef7373547858c1e38e9572b4b8c8b18e998ae4b9ba745b8111c2bfb99740b4ae4050a4674f32732c03bc0df08153dfcef5f3b9",
    },

