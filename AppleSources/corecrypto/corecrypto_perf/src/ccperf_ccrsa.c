/* Copyright (c) (2011-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccperf.h"
#include <corecrypto/ccrsa.h>
#include <corecrypto/ccrsa_priv.h>
#include <corecrypto/ccsha2.h>
#include "testbyteBuffer.h"

static cc_size grsakey_nbits = 0;

static struct ccrsa_full_ctx *grsakey;

const uint8_t e65537[] = { 0x01, 0x00, 0x01 };

struct rsa_keys {
    cc_size nbits;
    const char *der_full_key;
};

// Keys generated with the FIPS generation
const struct rsa_keys perf_rsa_keys[]={
    /* FIPS key */
{1024,"3082025c02010002818100bbc5d6ca74985f17abb0173f0ee07873a92b4d3742df2ec84d852c371db7692dd5f7e5b962209a2287cc594d41cf99b775affdf9b737d72e31917a32955dd00cc2e5eb3c3dcaa93b82c4349957ecff8a515e2ff84ef07e9ad2b3a969fb9868053b61d2edafa1d0c40ca66935d42fc14ec89bfd788d1bbcac82eb3d12b9612f0d020301000102818020e76cf96abf95b04bef6e4f683fb913c981f344bb04e989839e11ceb1b82567f90df8f548a6fe638d28e7c0344759002f5111001c955e3173d1b2986118c09f630283fc46521f8b6faefe62a0a30c9dcc70ee79ea473d8a787b853e6234403171bd32018cda0cb61e63a6045e166ad7d7074f712ad0ef4a77c10fdf654e7799024100dda9aaa1b4ffddbf7de0c89f7ca57663edae7c201b389faa902545ee72c6f129d2812ec6fa419780fce72feef6ccdfd2344fe9b447b14589ab810707b5d98d79024100d8dc389b1000bfa579dbc4cb1afd6943f80385200c0ef1f15b78fd48c17c4bf56006532ef1594196f119facc9af397b0d8261abe907ada4d331efc676b35cd35024100b811aaa639fdb790cae11cf883b38b4a94172ef0226ab4fc18533b6d3556caf125e32c8b0349f09ba667fcbffda647bef0bde39e57627812489f0ecd724f445102401a6f760309075e5558ae7ea5d7ab6e8a97902e4942cf0b9545765141ee3c2db242bb62a6854b41209a51756e3db1561b7bade172bb800e5e7ccdd92cee37c7c502402167c9eee9dd75ed1e3cf31105818e25a3ffa6c23a2e761abcbed113b13ecded24754c733a935ae0b4d594212b3f0a480975d2b77ae000387063748b526c8a1a"},
{1280,"308202eb0201000281a100937ff4212e55de42d3aab16053090e5db2ccbb785e7713cbbdea7e55ee134f8723d7facf5630144fa5596e4fe05942ea803e64b152727632489cc0598618e02372f87499cb48dc60cfb39942fe1ea5f9b4f9f6e12cfcd0378068fad2011d9dc13e8bbc934dd093641bcec49f7dce4fd69a0b8f083d0132ee5f7fccabdc59380c8651675c78f947f038d91fa06f16c8f4cfecd5e3255e44b5a1232965292295c702030100010281a0082521b30f5ef886123033d950dc88298e6d15d120ce4c8e8caf3d48bb7bdf8163ee52504ebf1af006fe7843faec92f066228be6ead99d434b95345dfd34b473e0ae6da9ec7ada88920fa5dff82e7315d07c967a20f55ad1bb34dc8e09672efd5170dc22c4b42bc249ad0b9575750693fc98784d05e59fcfa90a77b47fb488479852b835d50dac3c2ba40def27523bf7035017066f7c893d8f67e5743fd25109025100c5f1d23c8d206202edaf08daa5c7c7a9351795fc41d2e07cc70c940bab77e3a941db36cf5ae07aec2c9db521b7985be1195e1c784243080172649531184581cbb8972d5010e268b1c8a79d47793a5e2d025100bec29c47db3f201ad2a1a0d653416fa14ef9f220ff3117ac29de2efc4c658ed6775a16549938dc6b1d042281a04261c8c6451931cb5df2d6f2038828168f669f0fe65d339e5a8faea1b3040195b1b0430250543b432b612296928872236267894bfd450a745893ea187d0076e9c8cd7e86f24f83e91ef39cf2b1ed8a6eb99a56cb424e792dc43eee2749f653b6e8dd5b36906a4c6a8bd7a380c9a6892cf46d31d94102504c155cb5c03986398c87109a4b2c8f347c466e8f40993902ded4125368b91ce66746141ffbd8d4f917e29d4cac39adbca16fcfe3af6432460ed2dfcc756b0e98248451ea139fb52d06ab5aceb300e2f7025076771fc0c9f6531c228fdd5f99c0e7507e829fbeede25cd0e070e64f7484535c28f1ab94001f24cb1db02da60770811b96c6ec25e17ac6ed8fe69ea4d3ca1285e611c7b68d007169cd388a07ad53db0b"},
{1536,"3082037b0201000281c1009dd3c0fd7fdb19dd5e7c95202fb8571e9e307a06ee19a485627fe18d4bd85e0e3618e33c1fddc49c55f0ccc375b6a4debaf05d5a003540e4e5b653639066f25877ea219de3015f726f47ffa5e84054360628b4e78d970f8ff37bce92c66fc0f5c7dee2044d42edd995c5d5418b5667ebff944987cbcc877b16a04abf8f66b61a7660459fba5a71b7dc12adaa3a71eb559795eaf76c9c17feebe6ee50b667a4e5dde6701cd671cfc0ba40c2e7fdc5da1cbfaf2205d5efad54ca596cb6768c188b02030100010281c000b79d79141e2b9ec11701847d185cde53960bcfebeac0ea7c43f1834cb4c5d9fc5948f06a82a85494e2bc6e27a2f6052f1b4d894dabf048ba0485ef7e10ac5ef0e33c56352f0f3f26b8a5e046a46d8835fc9f09d85a61e48e6a371f9d4d950bbc6782a3e09c66e0bd88b84e3b013bd890d8625755a662afd88c36b74d376a8d2ebebd37eb27de348d7c7ad0f2dc77261cff933fb30a8634056f239b2a7e8879ae00d46641c6209e3f09eb75182b93739c7ab8ff0138f29d26ad4ad01559aa21026100ccb73a7442a84330fdf703bfe1f224bace371a5923e6656c0582920e1703f3487d739d356280ac402cfc879baacee2a05a1c72dcccf3d6ca7eae9260b8b50c21fb231c0d1568ff348bd62c1202fd133b21794c69d735d5e65448d49ff250f5ab026100c55d7b1b36eac1be7197a8b88c7c0732515a7209d8b422257ff21683664a9b56f24236ad5a2ed79608736f7745ca4719ae0e3e6c07e637daa13a54832c3a6e2da0b6a982ed41c7c6356fbff03aac73584b439bae6e387a5f74ae5425d91cc8a1026066b32d421206b3deaa29f7d9959292d69c898c5057f047c54f6657bb75d46782605d55eae845c12458ed3f62dae7fb4d92a75f00625999d1f087c7ab7a3e699dca8dac8eebc4c6f3278c0483ecb7e5a3ee8119d2a742bcd2564a4b510a918f0d02604a3105e20916de95f4a58a2b35c43a00544ca7a9c3e8931d7da7478745a0ae1c551d46e88b8a2848a20ca2ce3751fec04c89d6354e12e0d432df767d88d6be2c30c9f996da116c43ba3ab3f05e5e0d4e179ce69cff9a0386769a41cfa87a058102602105ef0235524463d4512f1efcb55efc1900f2bafb4bf03f426adde4b34d7b4472350e62f094f2dd0e44e5780dfb4a7c70c7963d179acf1a512864d0cc18101bde1221c785f5fa8c8a2b91bb5c6435a30d88a83fcda535534d315fe4a486836c"},
{2048,"308204a40201000282010100b7599b00d65e375472f7081ceef69940d1b28b309f204c2ee504d1ef268dec50e0ff045ac41ac0fcd86798d010f46db6c0e2404a34f702bd0f2ff17044a72a9a1f8ec668745db2ee29e5e470272638544d5455d729c035bff443ff199a0c8e691cb89b612931c7d194a66b62952addfd20f028b1850414bffb332cbb6d8f74620b627383253c7435d52997dde210214378c38f4ad821804532b246f15f1183699d3eb887230044aaa4d1169e03f90bdad442eb2c32f4e33a43ef89671d12126de8c79ca4746f885a660acbc2d4f1f8ee5dbd2855ef4630a983921a2f7052aa7474f9019ba592ef3ca763692b37999a2e0726826debf6cbdb3b55a9b200f1d4cf0203010001028201001513d9fbd8a8f0176737fad8c8a7d4aa5cf0f78b595faf225cf596e4b53bef84c4b8cc595addf07da0ab1828232ad64a02168069877935f961fb92f7e30c8c9b373184a1916f0c18d0fc3aaca1f384da3c218bd4b65a0053d6d2d24ab128ec5e2d0d13dfb18aa57bf468c54389fe6992a5ecb5e0e277bba2ee4fcdbea633ad9f3dc244ed61ad80358210bcfe29d5969271b50c73e6a9f0c41f507f3b35d52032571ca31a468e7d83d7842ad7407523c4c20efd1c09861a6481f58d87bd5619a06843f80a05b2b547465a65bd865c7e57b39e61fcd229b109b10a706a0d69988f5fc1d37a469b9e4697c0a85cf8cf180ecad5bde09ad37e8499b073b70b68db1102818100ee3e91f4bdfcdf188031b0ee799155b19de572bffc611803f0ca5cdf5416f1c48ddd6a7ab3f70113882419b9ef94d070f62af9320a0367d6d0a7f7890c8c807274da0fd3d39af8347a2dd72559a1533878b5c46265166c937812dcde69767841965862738862489354b3cbcd4eca673997d7fdc03b61f98ac4ea5c9b9d1a76ed02818100c503b69e48fa108fa10172c3692eee1773b945c2d17ec753abe677fa5b6e2a5da8babb28b7516f01290b3bf9eb0f354cfdb3f03e4d0647b81d60bb58a1e3fffd6d6420a00bf9e8391922795746eb17dfd38f865d8cd1ce6fd0c6c01ebe4ad566fbac44c4b00d59b9a1d0b4e4a1a78cbb631fbd128433758c30ee017776f0e72b02818100b38ca6552ba5dac0cd4425d2e3fd9af69c47e2fe3b8735212b24676fcc20ea9e36484b4a243d202b872ba5d3d27275d0dc4530befc7aea942376a3003f5bd825ea58b91aec5bdb7939273900a61705f00650feab25020c5beb5f53e3aed9a0f1d50bd14ebed74b58f5b9f6fb48c913987d0e43e7cf191c86efb6ac8a7e91065502818100b358ea09b5cd4efe3147ac3d8fa7153f6c2da0fff4ce408e3ed2932de9c5a3f3970246168eab272e1b3b0ae23bc5a073f210b8073eff1492dacb9040e33f376e7102d1606106a30c3781568cc91682a9536238a338ea55cf1c7391b96ae99cd31f107799c5daa16f878b02e18ef783f9a206e68bd0a537c0e35a0723c5b70ff90281801b36a4b3628a474e203b92b971b3e18b2a32e893576138675e38fdfa3721a0b5da76acd7cbf5dc7532e4fcf171fd9326950f09802a249d7ca8ac557d356026f3db8080c7f2fec249c44cd5b87fc54f3bcf6d7c37a1724f608e400559660aa280b8b7a6914104d46870a17159c71be156437d0100118fffda2671187eb0ca5a29"},
{3072,"308206e20201000282018100c68a38d81c6030175d59f3a20f76301ce82c43d34382c26a28884d0db37a6620dc95a1b689a25dbee2ba1cb4ec73e65688cfa4c04dfd15b3e407e1156d134ed3dcb18c3f63566c9e03f0144f021fc5d22bc80a301ddf944452c8f9b3129e0ff27a655ee35d75b12da68f6d48bdc577e1ba65711f20787764ea47c075246b95221fb3ee69a30f08628b0b02ddbab053b0695e281702f23ce388a953c6188d6cf4c180fc80e7d5ae1584fe190a548324d83a73f3e7f879f109b72bf94728d7d1520ccdada1375eae868ffb755d8faeb2c044b0554b1ac0dd5e590fe93746502c2d535d962363f0d2c19034542e7605b430b7a5e7e5ee81316388623e228ee5ed625ebe8c11cc6ddd2fd12c7ab515fd7e8b7b5d10bccb2bc0f6b70b55a4561c4520aa7335dd6e3600042cad04af0ddc5f76abb6eb77eb41fea38d88ca1baa0b6299621a9384eed1f100f22af5bd420e41d84395a387507b20b1e6b7ccc1b59f6d80fcf028c9e73a94716e71a54f5d77b66fb11ccb7df8665eab0bbfa36b6b83196d02030100010282018002581bda82f9a8914e0e43a3279d94a03f8cbb0c48212e1c77f80c05a8caa42da859e4bbe8d082f67304de5580893696d1c65042ac35dc2d8a2b84d8a1b7aa719a57ad860ae06bc11778cf9af99c0ba0e63f0967c208f05e388ccf54588bba6c131b161a53f19199616312f1745428c0008c68e01e35d45175504a5e0ae9d7df22ac4a98f2b4ec21d287a82734dbb08479506ab05c778b55b39f2dcbd72df919f6b621c51977a836bd3b739e3c9b36ff276321191d7824b7d4d93bde729f34ebad2731af5a362593af89099997f4d3a53b7051088dc9654eb25b07c63133edbb83f524d686d80ff16ce55500ccbdb11580d8d3bb88974ba95fd4f11c9d7b4dc411c5313a9e1beb2392dd1fb754e48ac06990a1639354fccdc2d85bd88c0733a1bc807c099fc527582ed3864f9a0158ca735afee8cc174ebf2647094113f57e960ef982b07f3d005a3677b13f6c57692bb51d6817d974b420ad83def42bac47bfdd0de12074a4b32170c4be7327e4e05efa4dc1d0414d4ea74723f55a50ec47e10281c100f0bbb3356463e56134e8a6a9a3b6c422e230001d0f2189865fd40961346cf444d01afc90f32522ef38ce926f63f0c3d9ae1d8fdc3f50c402c86028102eceda999622ddae59ccfcc8e2ee0eacb21d66e4de39ea81a58c8e2bc56d9f8df8f5de5851c330ebb6624e08fe4b46b157ae40f1073bfacfc1aa53ce6c4821d9f5ae9ae0b5307e808daa861d4216615d90d13c4f9534dc5354cf202aef3356d6a1924776e1408d00d5e41ae3729d05612b4c058cd8e02dd8fe9efc3875ae795fad5105190281c100d32183cd30a3a5cd510a9fc7b859fdae6d9172343138cdc23ffd917caf96f3038b93dab91f04547b7388545429ce32b50465047b626d04cf9d6e38c1eb223d679affa8e4b13e568bb7f46347c670961c6b2ac616a6215ebe9ede20b6a9751ed03e03f06581f9704c60b3041616bc1d65e66ef14134df504c17114de6a788ff7314aca86f4358a61aaa7cd211c0502c44c3fa1597a5bc8c9bdc89cc1ebef19d9f2e5d2bb8565d5d632410b2c14984554b086d8a62c541367394aa604733b58d750281c0594af62526d09b039c717368570e72e01190066ac0f30aa4ea24a73a040d29e9e05b3235bdca9793ae39893d820f8b45d1fcab20e1e75e5d3ddfd4dc73d04c6b4db22f11fdc3383c77581fdf54cded1d95845c04acd85edfc3826efd654c25a612e5d8de85af1f0cdcee2511a0d944c362908feec20220c5df8a3dec2fe20d16ae7e875dbdae73c2a481d2a9b70eb5553b9df8df7c04bc04d0e6f51df59e619da9dd9cafa3a6d1866e3bea03e9e06fea978347de464bc87854c65bc4ee6faff90281c0300f22f76428fc26de59b2c13d9f8e75540f959577d6dc4f694d88fe7ee1b773892420d79ecdd7853a693ff8e083455b9b227b80b288ea5d701294ecdf5f2de7158b38a0c60fd097814a2a073e8e863cf5d008c34311b9855e98658deec8f038aac52ec58c6e813781937e4ca0e43534eadd3a2183ad8993a87491ecfd19dc3c0feab5748e39f1a58445617414f8aafb04393b0d07f70172c122c4ca02e0f0e63921904027b89cf7625042c068c1acc0a5ac79a1be10f81a1b2f25374ff7f5b90281c040fca4a5d0384df21dbd835c0bf07cf36d6168fd7017a1d8a6779bcad5445384c4908c986a2626ace5fc96313a45f406229d95eb1830c10bf63761395df1d2ea63dba6304ac8ba2efaced687a7e6e3a577dcc8edfd4debeb2c52bece697b7e4829bd837c8e553037861b841f58a84acc4f855653fae368d52abaf3ab73814a48d0a8e3e1d8e518e1d4ec29925bd0cbc2bbdb564bfb833ee0508b3b5e88bc5b8890c094beff134e49b0639b0d01223d05ec708131acbb0e5adbfcd3816990db8b"},
{4096,"3082092802010002820201008c23f331ec2a647136da5ef5017023aec84a318f6bf696beb24ce554d3c627d58e0a141135a0a9212121848273bc2c4e27431d2097f5ec13c1cdde732341038c9b0a0403d608badfed65543077e9b5f4ee8f8167a96d4fb8e1767007b9e1635160cf8f0cc95b28ecacf5d72b09f0307c363452a8f2f1c5b7d81ae1e4bf822dd09a62b654d01c869f3dba93313c1a6506d7b0b60d5766f4ea83b55ebb76841ed6c58292f3affb079a6d9189cf23e421f21a8f2aad1c102f024044ef2e3b3d729f051d01c7d0b60ec79f3fd162f15cba9b7abe94711827b319935729c48a2b9bd60c331cc1276bde2add210e9f118ae3c6deb61b5191be55f307e2a5d0f0c5b54c0628ed52f567b6f3a92b8b220666119764689910fd232d5553690f3dc854af5ce7945a25c845e174130e92f2828c73eb5c6138d7ebc8d50b42bd0523f90b6435f0e82c4e11e60b4a2b3ad3435a9fabf03fd23278faaf2d0464ba25a5d78b05ba05cbf0703af75cbc1b04cce7c367ba88c21719a0049116bc4064d7fa17933d923418f15d6ff54b776b19f6cf052286417db75f286064fea0a8eac608a18075bd9f62a7ea91f696dac6daa332ee50dd4b8d67892c93c96267fa2b3b2f7a3e7121692260384d135d706f19c39da5a1a3c8892cb84dd8fd71b3d1976b69d6cd0c360282576b552dd57ff082e9914190667e64072c5cf08f48cd7dccba7926636e4702030100010282020007669aa0474d91d25cc8397d8cdee43385c64d49bab4e20f1e116b87084c0dac7c7cd1c47ae58a2902bbe768903e1ec4ddd3f084d921969f107c13c456d7471db4ce5999ee42b5c3bfa0bb4a77fab2ae45aef4718a0408d2c5ad608b37e8cc3aeef6e72210bc2cb41b0a3c9bbc419ffddf4af2169405eaa023dc7f9379fda0f7c43f744b9455fd52098b81dc76c51a12bb6f4c9df5c0ad2c795a29af92b9b57b3821062bb25e7a6f505c00401d301e0ed0124179b4e2b1e8d7860c6f8f97562749b8d7703af8725d5e6e9b5b334de758f0a981e35b1835a02324d642d7dd27b4ad1e41e57d7477de21a16e493e3eec7a832670d8e4ee7d51815819d3a7f378f87fd1e5f981f1bfdc573f0f841ac51d2ea6f1c9f1fa28d5a9eb86e04456460e5b14b49a7c2db55ef4931d59681c06953e936b7945d1746031c5becbb430635e193667b9dda9ff02fe8d65c33dfbd807fe588b86367d916d948f890fe8ebd3c4c6bf510ad87bce63ad004683e530d8150f03fbfb782379ba44c88f302f9bc965805a4c02b68ba939664684dcbc7a495bc0a5a0dcb81f194c80bf962aae3be024b15206f19de617a6829d8d2f84a86c3d5cc0aa9731ef2763f3cf98b4eceabee51f0ad085a0210468fb57348840503b57959f064a45f51c88f8c7b941ef23f9c12003ddaea2d58d0fe573a876e7463ba384424a3dcd3075f72b6f5d44b18658f1090282010100c47737e67f600fac168a1ce5fb75b321978632dbf7acadc674e1ebf2b94b12e13ddb7d611989cdd908773f6c410ae7e2bedbe844838c2b3e2e292a606401f34a39a35171bcd686106e4b57ebb89e34144540febd861db39fdc3559cd9e38db6ce8dd6cee6251d323a4e35deb982071850e363def6073a9644454bf6deb0f02ee7e933eb15cf8c9949573b353e5edb19f8c384c0838f6096a04c1acfacc7fc6dcfed83ae042e215bb671a685e9e2fd11df8a2a5e7f7d1661a52335989db1ea125db23b0e76cef5cb838d23f9a01029004a59bb53ed2ec7c9dd3cf05cdf782478f74f840196fca90f4a1f3fcfc8f18aeadd9ddb2cc39b9734e80d77f79324bfcdb0282010100b69b4fd63d6d13a2786aa37a8613f35f86e100850bc395c42f7682b1e82cfeb380ea67fd8c85709614951195fa982933b060f21928e82517dd93f8214aa8a7fbbabffd72ca9e470d2e4dbe145102bcd7b90abf74769246dfc0fbc6bdfc2c52cc089b36fc8269121c205d558fe68af8e6a16301b33be7bef72ca94cee6777c80253eecdecc4863ac44acd985eb78444b139f24a2886991317b765f3f786dd94a8a79f3cad6d838eef4a768daf1ca7d4d9ec194b5ff3858cf7d050e62fd0fdf2031aa3736dacd7726ce65492f78cfa37dd23ff9217b92d9392f1b92f5c9027b3490f26f0273405bd842a3f256828ac66ae28c8cb0b8dd8991bfb0e85deaa4fda05028201004c678cced0347c83d1542efee5b7154df80e9192e8143894987a0ff79a45eef6b7c6b750deccafc83ab99d69ad35df8e57e94fbfed64c2a070f5436caf17ef14ababaf0dcb81a62b97a9276d1da430debd3c14958225e4e8438c5ffb4e10108d9f561579f3b49ca71d05eb4da720dee4feeceb533fb05b6d0a01e75c88f092944b9759e7421fe2cd2cfe0cfc90cbcaab20adf82bae73489ff96f94a508889cbeef410a4c92d637db64b2696a7a9c5ff806ecc2169f52c9216d5c58f2facb43a26441d2177e4eec411c9fef6a2600681fd683e28da71b9f2f05e359ff8ac518ad5ab0fcc4a7ac208972be5f619d08dd4df10f7dec5c7a99b42af923b2ef738bc7028201004f8c9d5d11696132580eeca4c5a00f57c02468db8ce2696e0bd72edc5deeac0e7acca2fcbba8ae01537a152d26fbfe86fc015fb64231cf66f42a2fe020ec1431ff8affd870183f8fa86a49b20410933fcee6b5bd00a27ca9a1228dd3d9f55d2471635cb2e804e9d4c2eca60788416668e24985461584c196602868d13ad5dd95d606a442cee242db9c52b05c22ca463a86a9dc5087424c24faca395bcdaeddc21333b5753fce1e087481ecfb2a1a9b094c674084ce4b91bbab4e72d8c5ccbb0f4b1d857d73dc6f86ad588ea5b50e94238c391be5a5d00b07eab1e7c6052ea655df79f108c30af5228c5cf1e8cc3f3e84045464cfe5bd4406027ab32aeb3ada19028201010080decc32a718fc17adfefe88abac2f087b5c13f25da2a2e30eee6f3921c9dbdea342c11732d1bb7a838920269f7984dd0432146daf900794bd85c9fd1b21e5d839c43a1c4a59b68a0fa89a40c9cb9937b14e7c118577dbe7c02df81178cb6da5d53909c6e161dc0691537a6e6e475c14b0406c112c9c9a737d68f7ae201f79d2c30855451d2a3676a4d8e648259826a3e02b7791b87cabd49f94e9e6b95d2f08aa20e18962fb42b5cc15dc8364ad2883460818bee776d6cffc2c74bccef9825be6093d7eaf65e3c90cb65414f3a3003f041cd9e1748f0547ba8d7c665ef3375e347e94a297376162da50ffa6be02e4ff3130a93734d9900a56f9ad7534af4134"},

};


static void update_gkey(cc_size nbits) {
    if (grsakey==NULL
        || grsakey_nbits != nbits) {
        grsakey_nbits = nbits;
        grsakey=realloc(grsakey, ccrsa_full_ctx_size(ccn_sizeof(nbits)));
        byteBuffer foundKey=NULL;
        int ret=-1;
        ccrsa_ctx_n(grsakey)=ccn_nof(nbits);
        // Look for a key of size nbits in the precomputed keys
        for(size_t i=0;i<CC_ARRAY_LEN(perf_rsa_keys);i++) {
            if (perf_rsa_keys[i].nbits==nbits) {
                foundKey=hexStringToBytes(perf_rsa_keys[i].der_full_key);
                break;
            }
        }
        if (foundKey!=NULL) {
            ret=ccrsa_import_priv(grsakey, foundKey->len, foundKey->bytes);
            free(foundKey);
            foundKey=NULL;
        }
        else {
            ret = ccrsa_generate_fips186_key(nbits, grsakey, sizeof(e65537), e65537, rng, rng);
        }

        if (ret) abort();
    }
}

#if !CC_DISABLE_RSAKEYGEN
static double internal_ccrsa_generate_key(int doFIPS186, size_t loops, cc_size nbits)
{
    ccrsa_full_ctx_decl_nbits(nbits, key);

    int ret;
    perf_start();
    do {
        if(!doFIPS186) ret = ccrsa_generate_key(nbits, key, sizeof(e65537), e65537, rng);
        else ret = ccrsa_generate_fips186_key(nbits, key, sizeof(e65537), e65537, rng, rng);
        if (ret) abort();
    } while (--loops != 0);
    ccrsa_full_ctx_clear_nbits(nbits, key);
    return perf_seconds();
}
#endif /* CC_DISABLE_RSAKEYGEN */

static double internal_ccrsa_sign(int isPSS, size_t loops, cc_size nbits)
{
    uint8_t sig[ccn_sizeof(nbits)];
    size_t siglen = sizeof(sig);
    uint8_t digest[CCSHA256_OUTPUT_SIZE] = "01234567890123456789abcdefghijkl";
    int ret;

    update_gkey(nbits);

    // PSS
    if (isPSS) {
        perf_start();
        do {
            ret = ccrsa_sign_pss(grsakey, ccsha256_di(),ccsha256_di(), 20, rng,
                                 CCSHA256_OUTPUT_SIZE, digest,
                                 &siglen, sig);
            if (ret) abort();
        } while (--loops != 0);
        return perf_seconds();
    }

    // PKCS v1.5
    perf_start();
    do {
        ret = ccrsa_sign_pkcs1v15(grsakey, ccoid_sha256, CCSHA256_OUTPUT_SIZE, digest, &siglen, sig);
        if (ret) abort();
    } while (--loops != 0);
    return perf_seconds();
}

static double internal_ccrsa_verify(int isPSS, size_t loops, cc_size nbits)
{
    uint8_t sig[ccn_sizeof(nbits)];
    size_t siglen = sizeof(sig);
    uint8_t digest[CCSHA256_OUTPUT_SIZE] = "01234567890123456789abcdefghijkl";
    int ret;

    update_gkey(nbits);

    // Signature generation
    if (isPSS) {
        ret = ccrsa_sign_pss(grsakey, ccsha256_di(),ccsha256_di(), CCSHA256_OUTPUT_SIZE, rng,
                                   CCSHA256_OUTPUT_SIZE, digest,
                                   &siglen, sig);
    } else {
        ret = ccrsa_sign_pkcs1v15(grsakey, ccoid_sha256, CCSHA256_OUTPUT_SIZE, digest, &siglen, sig);
    }
    if (ret) abort();

    // PSS verify
    if (isPSS) {
        perf_start();
        do {
            ret = ccrsa_verify_pss_digest(ccrsa_ctx_public(grsakey), ccsha256_di(),
                                          ccsha256_di(), CCSHA256_OUTPUT_SIZE, digest,
                                          siglen, sig, CCSHA256_OUTPUT_SIZE, NULL);
            if (ret != CCERR_VALID_SIGNATURE) abort();
        } while (--loops != 0);
        return perf_seconds();
    }

    // PKCS verify
    perf_start();
    do {
        ret = ccrsa_verify_pkcs1v15_digest(ccrsa_ctx_public(grsakey), ccoid_sha256,
                                           CCSHA256_OUTPUT_SIZE, digest,
                                           siglen, sig, NULL);
        if (ret != CCERR_VALID_SIGNATURE) abort();
    } while (--loops != 0);
    return perf_seconds();
}

#if !CC_DISABLE_RSAKEYGEN
// Key gen
static double perf_ccrsa_generate_key(size_t loops, cc_size nbits)
{
    return internal_ccrsa_generate_key(0, loops, nbits);
}
static double perf_ccrsa_generate_fips186_key(size_t loops, cc_size nbits)
{
    return internal_ccrsa_generate_key(1, loops, nbits);
}
#endif /* CC_DISABLE_RSAKEYGEN */

// PKCS 1.5
static double perf_ccrsa_sign_pkcs15(size_t loops, cc_size nbits)
{
    return internal_ccrsa_sign(0, loops, nbits);
}

static double perf_ccrsa_verify_pkcs15(size_t loops, cc_size nbits)
{
    return internal_ccrsa_verify(0, loops, nbits);
}

// PSS
static double perf_ccrsa_sign_pss(size_t loops, cc_size nbits)
{
    return internal_ccrsa_sign(1, loops, nbits);
}

static double perf_ccrsa_verify_pss(size_t loops, cc_size nbits)
{
    return internal_ccrsa_verify(1, loops, nbits);
}

// Encryption OAEP
static double perf_ccrsa_encrypt_oaep(size_t loops, cc_size nbits)
{
    uint8_t cipher[ccn_sizeof(nbits)];
    size_t cipherlen = sizeof(cipher);
    uint8_t message[] = "01234567890123456789abcdefghijkl";
    int ret;

    update_gkey(nbits);

    // PKCS v1.5
    perf_start();
    do {
        cipherlen = sizeof(cipher);
        ret = ccrsa_encrypt_oaep(ccrsa_ctx_public(grsakey),ccsha256_di(),rng,
                                &cipherlen,cipher,
                                 sizeof(message), message,
                                 0, NULL);
        if (ret) abort();
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_ccrsa_decrypt_oaep(size_t loops, cc_size nbits)
{
    uint8_t cipher[ccn_sizeof(nbits)];
    size_t  cipherlen = sizeof(cipher);
    uint8_t plain[ccn_sizeof(nbits)];
    size_t  plainlen = sizeof(plain);
    uint8_t message[] = "01234567890123456789abcdefghijkl";

    int ret;

    update_gkey(nbits);

    ret = ccrsa_encrypt_oaep(ccrsa_ctx_public(grsakey),ccsha256_di(),rng,
                             &cipherlen,cipher,
                             sizeof(message), message,
                             0, NULL);
    if (ret) abort();

    // PKCS
    perf_start();
    do {
        plainlen = sizeof(plain);
        ret = ccrsa_decrypt_oaep(grsakey,ccsha256_di(),
                                 &plainlen,plain,
                                 cipherlen, cipher,
                                 0, NULL);
        if (ret) abort();
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_ccrsa_make_priv(size_t loops, cc_size nbits)
{
    update_gkey(nbits);

    cc_size n = ccrsa_ctx_n(grsakey);
    cczp_t zp = ccrsa_ctx_private_zp(grsakey);
    cczp_t zq = ccrsa_ctx_private_zq(grsakey);
    cc_size pn = cczp_n(zp);
    cc_size qn = cczp_n(zq);

    uint8_t e_buf[ccn_write_uint_size(n, ccrsa_ctx_e(grsakey))];
    ccn_write_uint(n, ccrsa_ctx_e(grsakey), sizeof(e_buf), e_buf);

    uint8_t p_buf[ccn_write_uint_size(pn, cczp_prime(zp))];
    ccn_write_uint(pn, cczp_prime(zp), sizeof(p_buf), p_buf);

    uint8_t q_buf[ccn_write_uint_size(qn, cczp_prime(zq))];
    ccn_write_uint(qn, cczp_prime(zq), sizeof(q_buf), q_buf);

    perf_start();
    do {
        if (ccrsa_make_priv(grsakey, sizeof(e_buf), e_buf,
                                     sizeof(p_buf), p_buf,
                                     sizeof(q_buf), q_buf)) {
            abort();
        }
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_ccrsa_recover_priv(size_t loops, cc_size nbits)
{
    update_gkey(nbits);

    cc_size n = ccrsa_ctx_n(grsakey);
    cczp_t zm = ccrsa_ctx_zm(grsakey);

    uint8_t m_buf[ccn_write_uint_size(n, cczp_prime(zm))];
    ccn_write_uint(n, cczp_prime(zm), sizeof(m_buf), m_buf);

    uint8_t e_buf[ccn_write_uint_size(n, ccrsa_ctx_e(grsakey))];
    ccn_write_uint(n, ccrsa_ctx_e(grsakey), sizeof(e_buf), e_buf);

    uint8_t d_buf[ccn_write_uint_size(n, ccrsa_ctx_d(grsakey))];
    ccn_write_uint(n, ccrsa_ctx_d(grsakey), sizeof(d_buf), d_buf);

    perf_start();
    do {
        if (ccrsa_recover_priv(grsakey, sizeof(m_buf), m_buf,
                                        sizeof(e_buf), e_buf,
                                        sizeof(d_buf), d_buf, rng)) {
            abort();
        }
    } while (--loops != 0);
    return perf_seconds();
}

#define _TEST(_x) { .name = #_x, .func = perf_ ## _x}
static struct ccrsa_perf_test {
    const char *name;
    double(*func)(size_t loops, cc_size nbits);
} ccrsa_perf_tests[] = {
    _TEST(ccrsa_sign_pkcs15),
    _TEST(ccrsa_verify_pkcs15),
    _TEST(ccrsa_sign_pss),
    _TEST(ccrsa_verify_pss),
    _TEST(ccrsa_encrypt_oaep),
    _TEST(ccrsa_decrypt_oaep),
    _TEST(ccrsa_make_priv),
    _TEST(ccrsa_recover_priv),
};

static double perf_ccrsa(size_t loops, size_t *psize, const void *arg)
{
    const struct ccrsa_perf_test *test=arg;
    return test->func(loops, *psize);
}

static struct ccperf_family family;

struct ccperf_family *ccperf_family_ccrsa(int argc, char *argv[])
{
    F_GET_ALL(family, ccrsa);
    static const size_t key_nbits[]={1024,1280,2048,4096};
    F_SIZES_FROM_ARRAY(family,key_nbits);

    family.size_kind=ccperf_size_bits;
    return &family;
}

static struct ccrsa_keygen_perf_test {
    const char *name;
    double(*func)(size_t loops, cc_size nbits);
} ccrsa_keygen_perf_tests[] = {
#if !CC_DISABLE_RSAKEYGEN
    _TEST(ccrsa_generate_key),
    _TEST(ccrsa_generate_fips186_key),
#endif // CC_DISABLE_RSAKEYGEN
};

static double perf_ccrsa_keygen(size_t loops, size_t *psize, const void *arg)
{
    const struct ccrsa_keygen_perf_test *test=arg;
    return test->func(loops, *psize);
}

static struct ccperf_family family_keygen;

struct ccperf_family *ccperf_family_ccrsa_keygen(int argc, char *argv[])
{
    F_GET_ALL(family_keygen, ccrsa_keygen);
    static const size_t key_nbits[]={1024,1280,2048,4096};
    F_SIZES_FROM_ARRAY(family_keygen, key_nbits);
    family.size_kind=ccperf_size_bits;
    return &family_keygen;
}
