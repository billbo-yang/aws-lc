/* Copyright (c) 2015, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

 /* This file was generated by err_data_generate.go. */

#include <openssl/base.h>
#include <openssl/err.h>
#include <openssl/type_check.h>


OPENSSL_STATIC_ASSERT(ERR_LIB_NONE == 1, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_SYS == 2, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_BN == 3, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_RSA == 4, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_DH == 5, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_EVP == 6, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_BUF == 7, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_OBJ == 8, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_PEM == 9, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_DSA == 10, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_X509 == 11, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_ASN1 == 12, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_CONF == 13, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_CRYPTO == 14, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_EC == 15, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_SSL == 16, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_BIO == 17, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_PKCS7 == 18, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_PKCS8 == 19, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_X509V3 == 20, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_RAND == 21, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_ENGINE == 22, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_OCSP == 23, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_UI == 24, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_COMP == 25, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_ECDSA == 26, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_ECDH == 27, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_HMAC == 28, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_DIGEST == 29, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_CIPHER == 30, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_HKDF == 31, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_TRUST_TOKEN == 32, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_LIB_USER == 33, library_value_changed);
OPENSSL_STATIC_ASSERT(ERR_NUM_LIBS == 34, number_of_libraries_changed);

const uint32_t kOpenSSLReasonValues[] = {
    0xc320847,
    0xc328861,
    0xc330870,
    0xc338880,
    0xc34088f,
    0xc3488a8,
    0xc3508b4,
    0xc3588d1,
    0xc3608f1,
    0xc3688ff,
    0xc37090f,
    0xc37891c,
    0xc38092c,
    0xc388937,
    0xc39094d,
    0xc39895c,
    0xc3a0970,
    0xc3a8854,
    0xc3b00f7,
    0xc3b88e3,
    0x10320854,
    0x103295ee,
    0x103315fa,
    0x10339613,
    0x10341626,
    0x10348f34,
    0x10350c6d,
    0x10359639,
    0x10361663,
    0x10369676,
    0x10371695,
    0x103796ae,
    0x103816c3,
    0x103896e1,
    0x103916f0,
    0x1039970c,
    0x103a1727,
    0x103a9736,
    0x103b1752,
    0x103b976d,
    0x103c1793,
    0x103c80f7,
    0x103d17a4,
    0x103d97b8,
    0x103e17d7,
    0x103e97e6,
    0x103f17fd,
    0x103f9810,
    0x10400c31,
    0x10409823,
    0x10411841,
    0x10419854,
    0x1042186e,
    0x1042987e,
    0x10431892,
    0x104398a8,
    0x104418c0,
    0x104498d5,
    0x104518e9,
    0x104598fb,
    0x1046060a,
    0x1046895c,
    0x10471910,
    0x10479927,
    0x1048193c,
    0x1048994a,
    0x10490e80,
    0x10499784,
    0x104a164e,
    0x14320c14,
    0x14328c22,
    0x14330c31,
    0x14338c43,
    0x143400b9,
    0x143480f7,
    0x18320090,
    0x18328f8a,
    0x183300b9,
    0x18338fa0,
    0x18340fb4,
    0x183480f7,
    0x18350fd3,
    0x18358feb,
    0x18361000,
    0x18369014,
    0x1837104c,
    0x18379062,
    0x18381076,
    0x18389086,
    0x18390a82,
    0x18399096,
    0x183a10bc,
    0x183a90e2,
    0x183b0c8c,
    0x183b9131,
    0x183c1143,
    0x183c914e,
    0x183d115e,
    0x183d916f,
    0x183e1180,
    0x183e9192,
    0x183f11bb,
    0x183f91d4,
    0x184011ec,
    0x184086e2,
    0x18411105,
    0x184190d0,
    0x184210ef,
    0x18428c79,
    0x184310ab,
    0x18439117,
    0x18440fc9,
    0x18449038,
    0x20321226,
    0x20329213,
    0x24321256,
    0x243289a2,
    0x24331268,
    0x24339275,
    0x24341282,
    0x24349294,
    0x243512a3,
    0x243592c0,
    0x243612cd,
    0x243692db,
    0x243712e9,
    0x243792f7,
    0x24381300,
    0x2438930d,
    0x24391320,
    0x28320c61,
    0x28328c8c,
    0x28330c31,
    0x28338c9f,
    0x28340c6d,
    0x283480b9,
    0x283500f7,
    0x28358c79,
    0x2c323202,
    0x2c329337,
    0x2c333210,
    0x2c33b222,
    0x2c343236,
    0x2c34b248,
    0x2c353263,
    0x2c35b275,
    0x2c3632a5,
    0x2c36833a,
    0x2c3732b2,
    0x2c37b2de,
    0x2c383303,
    0x2c38b31a,
    0x2c393338,
    0x2c39b348,
    0x2c3a335a,
    0x2c3ab36e,
    0x2c3b337f,
    0x2c3bb39e,
    0x2c3c1349,
    0x2c3c935f,
    0x2c3d33b2,
    0x2c3d9378,
    0x2c3e33cf,
    0x2c3eb3dd,
    0x2c3f33f5,
    0x2c3fb40d,
    0x2c403437,
    0x2c409226,
    0x2c413448,
    0x2c41b45b,
    0x2c4211ec,
    0x2c42b46c,
    0x2c43072f,
    0x2c43b390,
    0x2c4432f1,
    0x2c44b41a,
    0x2c453288,
    0x2c45b2c4,
    0x2c463328,
    0x30320000,
    0x30328015,
    0x3033001f,
    0x30338038,
    0x30340057,
    0x30348071,
    0x30350078,
    0x30358090,
    0x303600a1,
    0x303680b9,
    0x303700c6,
    0x303780d5,
    0x303800f7,
    0x30388104,
    0x30390117,
    0x30398132,
    0x303a0147,
    0x303a815b,
    0x303b016f,
    0x303b8180,
    0x303c0199,
    0x303c81b6,
    0x303d01c4,
    0x303d81d8,
    0x303e01e8,
    0x303e8201,
    0x303f0211,
    0x303f8224,
    0x30400233,
    0x3040823f,
    0x30410254,
    0x30418264,
    0x3042027b,
    0x30428288,
    0x3043029b,
    0x304382aa,
    0x304402bf,
    0x304482e0,
    0x304502f3,
    0x30458306,
    0x3046031f,
    0x3046833a,
    0x30470357,
    0x30478369,
    0x30480377,
    0x30488388,
    0x30490397,
    0x304983af,
    0x304a03c1,
    0x304a83d5,
    0x304b03ed,
    0x304b8400,
    0x304c040b,
    0x304c841c,
    0x304d0428,
    0x304d843e,
    0x304e044c,
    0x304e8462,
    0x304f0474,
    0x304f8486,
    0x305004a9,
    0x305084bc,
    0x305104cd,
    0x305184dd,
    0x305204f5,
    0x3052850a,
    0x30530522,
    0x30538536,
    0x3054054e,
    0x30548567,
    0x30550580,
    0x3055859d,
    0x305605a8,
    0x305685c0,
    0x305705d0,
    0x305785e1,
    0x305805f4,
    0x3058860a,
    0x30590613,
    0x30598628,
    0x305a063b,
    0x305a864a,
    0x305b066a,
    0x305b8679,
    0x305c069a,
    0x305c86b6,
    0x305d06c2,
    0x305d86e2,
    0x305e06fe,
    0x305e870f,
    0x305f0725,
    0x305f872f,
    0x30600499,
    0x3060804a,
    0x34320b72,
    0x34328b86,
    0x34330ba3,
    0x34338bb6,
    0x34340bc5,
    0x34348bfe,
    0x34350be2,
    0x3c320090,
    0x3c328cc9,
    0x3c330ce2,
    0x3c338cfd,
    0x3c340d1a,
    0x3c348d44,
    0x3c350d5f,
    0x3c358d85,
    0x3c360d9e,
    0x3c368db6,
    0x3c370dc7,
    0x3c378dd5,
    0x3c380de2,
    0x3c388df6,
    0x3c390c8c,
    0x3c398e19,
    0x3c3a0e2d,
    0x3c3a891c,
    0x3c3b0e3d,
    0x3c3b8e58,
    0x3c3c0e6a,
    0x3c3c8e9d,
    0x3c3d0ea7,
    0x3c3d8ebb,
    0x3c3e0ec9,
    0x3c3e8eee,
    0x3c3f0cb5,
    0x3c3f8ed7,
    0x3c4000b9,
    0x3c4080f7,
    0x3c410d35,
    0x3c418d74,
    0x3c420e80,
    0x3c428e0a,
    0x403219dc,
    0x403299f2,
    0x40331a20,
    0x40339a2a,
    0x40341a41,
    0x40349a5f,
    0x40351a6f,
    0x40359a81,
    0x40361a8e,
    0x40369a9a,
    0x40371aaf,
    0x40379ac1,
    0x40381acc,
    0x40389ade,
    0x40390f34,
    0x40399aee,
    0x403a1b01,
    0x403a9b22,
    0x403b1b33,
    0x403b9b43,
    0x403c0071,
    0x403c8090,
    0x403d1ba4,
    0x403d9bba,
    0x403e1bc9,
    0x403e9c01,
    0x403f1c1b,
    0x403f9c43,
    0x40401c58,
    0x40409c6c,
    0x40411ca7,
    0x40419cc2,
    0x40421cdb,
    0x40429cee,
    0x40431d02,
    0x40439d30,
    0x40441d47,
    0x404480b9,
    0x40451d5c,
    0x40459d6e,
    0x40461d92,
    0x40469db2,
    0x40471dc0,
    0x40479de7,
    0x40481e58,
    0x40489f05,
    0x40491f1c,
    0x40499f36,
    0x404a1f4d,
    0x404a9f6b,
    0x404b1f83,
    0x404b9fb0,
    0x404c1fc6,
    0x404c9fd8,
    0x404d1ff9,
    0x404da032,
    0x404e2046,
    0x404ea053,
    0x404f20d0,
    0x404fa116,
    0x4050216d,
    0x4050a181,
    0x405121b4,
    0x405221c4,
    0x4052a1e8,
    0x40532200,
    0x4053a213,
    0x40542228,
    0x4054a24b,
    0x40552276,
    0x4055a2b3,
    0x405622d8,
    0x4056a2f1,
    0x40572309,
    0x4057a31c,
    0x40582331,
    0x4058a358,
    0x40592387,
    0x4059a3b4,
    0x405a23c8,
    0x405aa3d8,
    0x405b23f0,
    0x405ba401,
    0x405c2414,
    0x405ca453,
    0x405d2460,
    0x405da485,
    0x405e24c3,
    0x405e8ac0,
    0x405f24e4,
    0x405fa4f1,
    0x406024ff,
    0x4060a521,
    0x40612582,
    0x4061a5ba,
    0x406225d1,
    0x4062a5e2,
    0x4063262f,
    0x4063a644,
    0x4064265b,
    0x4064a687,
    0x406526a2,
    0x4065a6b9,
    0x406626d1,
    0x4066a6fb,
    0x40672726,
    0x4067a76b,
    0x406827b3,
    0x4068a7d4,
    0x40692806,
    0x4069a834,
    0x406a2855,
    0x406aa875,
    0x406b29fd,
    0x406baa20,
    0x406c2a36,
    0x406cad27,
    0x406d2d56,
    0x406dad7e,
    0x406e2dac,
    0x406eadf9,
    0x406f2e52,
    0x406fae8a,
    0x40702e9d,
    0x4070aeba,
    0x4071080f,
    0x4071aecc,
    0x40722edf,
    0x4072af15,
    0x40732f2d,
    0x40739549,
    0x40742f41,
    0x4074af5b,
    0x40752f6c,
    0x4075af80,
    0x40762f8e,
    0x4076930d,
    0x40772fb3,
    0x4077aff3,
    0x4078300e,
    0x4078b047,
    0x4079305e,
    0x4079b074,
    0x407a30a0,
    0x407ab0b3,
    0x407b30c8,
    0x407bb0da,
    0x407c310b,
    0x407cb114,
    0x407d27ef,
    0x407da126,
    0x407e3023,
    0x407ea368,
    0x407f1dd4,
    0x407f9f9a,
    0x408020e0,
    0x40809dfc,
    0x408121d6,
    0x4081a084,
    0x40822d97,
    0x40829b4f,
    0x40832343,
    0x4083a66c,
    0x40841e10,
    0x4084a3a0,
    0x40852425,
    0x4085a549,
    0x408624a5,
    0x4086a140,
    0x40872ddd,
    0x4087a597,
    0x40881b8d,
    0x4088a77e,
    0x40891bdc,
    0x40899b69,
    0x408a2a6e,
    0x408a9961,
    0x408b30ef,
    0x408bae67,
    0x408c2435,
    0x408c9999,
    0x408d1eeb,
    0x408d9e42,
    0x408e201b,
    0x408ea293,
    0x408f2792,
    0x408fa565,
    0x40902747,
    0x4090a477,
    0x40912a56,
    0x409199bf,
    0x40921c29,
    0x4092ae18,
    0x40932ef8,
    0x4093a151,
    0x40941e24,
    0x4094aa87,
    0x409525f3,
    0x4095b080,
    0x40962dc4,
    0x4096a0f9,
    0x4097219c,
    0x4097a06a,
    0x40981c89,
    0x4098a607,
    0x40992e34,
    0x4099a2c0,
    0x409a2259,
    0x409a997d,
    0x409b1e71,
    0x409b9e9c,
    0x409c2fd5,
    0x409c9ec4,
    0x409d20b5,
    0x409da09a,
    0x409e1d1a,
    0x41f42928,
    0x41f929ba,
    0x41fe28ad,
    0x41feab63,
    0x41ff2c78,
    0x42032941,
    0x42082963,
    0x4208a99f,
    0x42092891,
    0x4209a9d9,
    0x420a28e8,
    0x420aa8c8,
    0x420b2908,
    0x420ba981,
    0x420c2c94,
    0x420caa97,
    0x420d2b4a,
    0x420dab81,
    0x42122b9b,
    0x42172c5b,
    0x4217abdd,
    0x421c2bff,
    0x421f2bba,
    0x42212d0c,
    0x42262c3e,
    0x422b2cea,
    0x422bab25,
    0x422c2ccc,
    0x422caad8,
    0x422d2ab1,
    0x422dacab,
    0x422e2b04,
    0x42302c1a,
    0x4432073a,
    0x44328749,
    0x44330755,
    0x44338763,
    0x44340776,
    0x44348787,
    0x4435078e,
    0x44358798,
    0x443607ab,
    0x443687c1,
    0x443707d3,
    0x443787e0,
    0x443807ef,
    0x443887f7,
    0x4439080f,
    0x4439881d,
    0x443a0830,
    0x48321337,
    0x48329349,
    0x4833135f,
    0x48339378,
    0x4c32139d,
    0x4c3293ad,
    0x4c3313c0,
    0x4c3393e0,
    0x4c3400b9,
    0x4c3480f7,
    0x4c3513ec,
    0x4c3593fa,
    0x4c361416,
    0x4c36943c,
    0x4c37144b,
    0x4c379459,
    0x4c38146e,
    0x4c38947a,
    0x4c39149a,
    0x4c3994c4,
    0x4c3a14dd,
    0x4c3a94f6,
    0x4c3b060a,
    0x4c3b950f,
    0x4c3c1521,
    0x4c3c9530,
    0x4c3d1549,
    0x4c3d8c54,
    0x4c3e15b6,
    0x4c3e9558,
    0x4c3f15d8,
    0x4c3f930d,
    0x4c40156e,
    0x4c409389,
    0x4c4115a6,
    0x4c419429,
    0x4c421592,
    0x5032347e,
    0x5032b48d,
    0x50333498,
    0x5033b4a8,
    0x503434c1,
    0x5034b4db,
    0x503534e9,
    0x5035b4ff,
    0x50363511,
    0x5036b527,
    0x50373540,
    0x5037b553,
    0x5038356b,
    0x5038b57c,
    0x50393591,
    0x5039b5a5,
    0x503a35c5,
    0x503ab5db,
    0x503b35f3,
    0x503bb605,
    0x503c3621,
    0x503cb638,
    0x503d3651,
    0x503db667,
    0x503e3674,
    0x503eb68a,
    0x503f369c,
    0x503f8388,
    0x504036af,
    0x5040b6bf,
    0x504136d9,
    0x5041b6e8,
    0x50423702,
    0x5042b71f,
    0x5043372f,
    0x5043b73f,
    0x5044374e,
    0x5044843e,
    0x50453762,
    0x5045b780,
    0x50463793,
    0x5046b7a9,
    0x504737bb,
    0x5047b7d0,
    0x504837f6,
    0x5048b804,
    0x50493817,
    0x5049b82c,
    0x504a3842,
    0x504ab852,
    0x504b3872,
    0x504bb885,
    0x504c38a8,
    0x504cb8d6,
    0x504d38e8,
    0x504db905,
    0x504e3920,
    0x504eb93c,
    0x504f394e,
    0x504fb965,
    0x50503974,
    0x505086fe,
    0x50513987,
    0x58320f72,
    0x5c341232,
    0x5c361245,
    0x68320f34,
    0x68328c8c,
    0x68330c9f,
    0x68338f42,
    0x68340f52,
    0x683480f7,
    0x6c320efa,
    0x6c328c43,
    0x6c330f05,
    0x6c338f1e,
    0x74320a28,
    0x743280b9,
    0x74330c54,
    0x7832098d,
    0x783289a2,
    0x783309ae,
    0x78338090,
    0x783409bd,
    0x783489d2,
    0x783509f1,
    0x78358a13,
    0x78360a28,
    0x78368a3e,
    0x78370a4e,
    0x78378a6f,
    0x78380a82,
    0x78388a94,
    0x78390aa1,
    0x78398ac0,
    0x783a0ad5,
    0x783a8ae3,
    0x783b0aed,
    0x783b8b01,
    0x783c0b18,
    0x783c8b2d,
    0x783d0b44,
    0x783d8b59,
    0x783e0aaf,
    0x783e8a61,
    0x7c321202,
    0x8032143c,
    0x80328090,
    0x803331d1,
    0x803380b9,
    0x803431e0,
    0x8034b148,
    0x80353166,
    0x8035b1f4,
    0x803631a8,
    0x8036b157,
    0x8037319a,
    0x8037b135,
    0x803831bb,
    0x8038b177,
    0x8039318c,
};

const size_t kOpenSSLReasonValuesLen = sizeof(kOpenSSLReasonValues) / sizeof(kOpenSSLReasonValues[0]);

const char kOpenSSLReasonStringData[] =
    "ASN1_LENGTH_MISMATCH\0"
    "AUX_ERROR\0"
    "BAD_GET_ASN1_OBJECT_CALL\0"
    "BAD_OBJECT_HEADER\0"
    "BAD_TEMPLATE\0"
    "BMPSTRING_IS_WRONG_LENGTH\0"
    "BN_LIB\0"
    "BOOLEAN_IS_WRONG_LENGTH\0"
    "BUFFER_TOO_SMALL\0"
    "CONTEXT_NOT_INITIALISED\0"
    "DECODE_ERROR\0"
    "DEPTH_EXCEEDED\0"
    "DIGEST_AND_KEY_TYPE_NOT_SUPPORTED\0"
    "ENCODE_ERROR\0"
    "ERROR_GETTING_TIME\0"
    "EXPECTING_AN_ASN1_SEQUENCE\0"
    "EXPECTING_AN_INTEGER\0"
    "EXPECTING_AN_OBJECT\0"
    "EXPECTING_A_BOOLEAN\0"
    "EXPECTING_A_TIME\0"
    "EXPLICIT_LENGTH_MISMATCH\0"
    "EXPLICIT_TAG_NOT_CONSTRUCTED\0"
    "FIELD_MISSING\0"
    "FIRST_NUM_TOO_LARGE\0"
    "HEADER_TOO_LONG\0"
    "ILLEGAL_BITSTRING_FORMAT\0"
    "ILLEGAL_BOOLEAN\0"
    "ILLEGAL_CHARACTERS\0"
    "ILLEGAL_FORMAT\0"
    "ILLEGAL_HEX\0"
    "ILLEGAL_IMPLICIT_TAG\0"
    "ILLEGAL_INTEGER\0"
    "ILLEGAL_NESTED_TAGGING\0"
    "ILLEGAL_NULL\0"
    "ILLEGAL_NULL_VALUE\0"
    "ILLEGAL_OBJECT\0"
    "ILLEGAL_OPTIONAL_ANY\0"
    "ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE\0"
    "ILLEGAL_TAGGED_ANY\0"
    "ILLEGAL_TIME_VALUE\0"
    "INTEGER_NOT_ASCII_FORMAT\0"
    "INTEGER_TOO_LARGE_FOR_LONG\0"
    "INVALID_BIT_STRING_BITS_LEFT\0"
    "INVALID_BMPSTRING\0"
    "INVALID_DIGIT\0"
    "INVALID_MODIFIER\0"
    "INVALID_NUMBER\0"
    "INVALID_OBJECT_ENCODING\0"
    "INVALID_SEPARATOR\0"
    "INVALID_TIME_FORMAT\0"
    "INVALID_UNIVERSALSTRING\0"
    "INVALID_UTF8STRING\0"
    "LIST_ERROR\0"
    "MISSING_ASN1_EOS\0"
    "MISSING_EOC\0"
    "MISSING_SECOND_NUMBER\0"
    "MISSING_VALUE\0"
    "MSTRING_NOT_UNIVERSAL\0"
    "MSTRING_WRONG_TAG\0"
    "NESTED_ASN1_ERROR\0"
    "NESTED_ASN1_STRING\0"
    "NESTED_TOO_DEEP\0"
    "NON_HEX_CHARACTERS\0"
    "NOT_ASCII_FORMAT\0"
    "NOT_ENOUGH_DATA\0"
    "NO_MATCHING_CHOICE_TYPE\0"
    "NULL_IS_WRONG_LENGTH\0"
    "OBJECT_NOT_ASCII_FORMAT\0"
    "ODD_NUMBER_OF_CHARS\0"
    "SECOND_NUMBER_TOO_LARGE\0"
    "SEQUENCE_LENGTH_MISMATCH\0"
    "SEQUENCE_NOT_CONSTRUCTED\0"
    "SEQUENCE_OR_SET_NEEDS_CONFIG\0"
    "SHORT_LINE\0"
    "STREAMING_NOT_SUPPORTED\0"
    "STRING_TOO_LONG\0"
    "STRING_TOO_SHORT\0"
    "TAG_VALUE_TOO_HIGH\0"
    "TIME_NOT_ASCII_FORMAT\0"
    "TOO_LONG\0"
    "TYPE_NOT_CONSTRUCTED\0"
    "TYPE_NOT_PRIMITIVE\0"
    "UNEXPECTED_EOC\0"
    "UNIVERSALSTRING_IS_WRONG_LENGTH\0"
    "UNKNOWN_FORMAT\0"
    "UNKNOWN_MESSAGE_DIGEST_ALGORITHM\0"
    "UNKNOWN_SIGNATURE_ALGORITHM\0"
    "UNKNOWN_TAG\0"
    "UNSUPPORTED_ANY_DEFINED_BY_TYPE\0"
    "UNSUPPORTED_PUBLIC_KEY_TYPE\0"
    "UNSUPPORTED_TYPE\0"
    "WRONG_PUBLIC_KEY_TYPE\0"
    "WRONG_TAG\0"
    "WRONG_TYPE\0"
    "BAD_FOPEN_MODE\0"
    "BROKEN_PIPE\0"
    "CONNECT_ERROR\0"
    "ERROR_SETTING_NBIO\0"
    "INVALID_ARGUMENT\0"
    "IN_USE\0"
    "KEEPALIVE\0"
    "NBIO_CONNECT_ERROR\0"
    "NO_HOSTNAME_SPECIFIED\0"
    "NO_PORT_SPECIFIED\0"
    "NO_SUCH_FILE\0"
    "NULL_PARAMETER\0"
    "SYS_LIB\0"
    "UNABLE_TO_CREATE_SOCKET\0"
    "UNINITIALIZED\0"
    "UNSUPPORTED_METHOD\0"
    "WRITE_TO_READ_ONLY_BIO\0"
    "ARG2_LT_ARG3\0"
    "BAD_ENCODING\0"
    "BAD_RECIPROCAL\0"
    "BIGNUM_TOO_LONG\0"
    "BITS_TOO_SMALL\0"
    "CALLED_WITH_EVEN_MODULUS\0"
    "DIV_BY_ZERO\0"
    "EXPAND_ON_STATIC_BIGNUM_DATA\0"
    "INPUT_NOT_REDUCED\0"
    "INVALID_INPUT\0"
    "INVALID_RANGE\0"
    "NEGATIVE_NUMBER\0"
    "NOT_A_SQUARE\0"
    "NOT_INITIALIZED\0"
    "NO_INVERSE\0"
    "PRIVATE_KEY_TOO_LARGE\0"
    "P_IS_NOT_PRIME\0"
    "TOO_MANY_ITERATIONS\0"
    "TOO_MANY_TEMPORARY_VARIABLES\0"
    "AES_KEY_SETUP_FAILED\0"
    "BAD_DECRYPT\0"
    "BAD_KEY_LENGTH\0"
    "CTRL_NOT_IMPLEMENTED\0"
    "CTRL_OPERATION_NOT_IMPLEMENTED\0"
    "DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH\0"
    "INITIALIZATION_ERROR\0"
    "INPUT_NOT_INITIALIZED\0"
    "INVALID_AD_SIZE\0"
    "INVALID_KEY_LENGTH\0"
    "INVALID_NONCE\0"
    "INVALID_NONCE_SIZE\0"
    "INVALID_OPERATION\0"
    "IV_TOO_LARGE\0"
    "NO_CIPHER_SET\0"
    "NO_DIRECTION_SET\0"
    "OUTPUT_ALIASES_INPUT\0"
    "TAG_TOO_LARGE\0"
    "TOO_LARGE\0"
    "UNSUPPORTED_AD_SIZE\0"
    "UNSUPPORTED_INPUT_SIZE\0"
    "UNSUPPORTED_KEY_SIZE\0"
    "UNSUPPORTED_NONCE_SIZE\0"
    "UNSUPPORTED_TAG_SIZE\0"
    "WRONG_FINAL_BLOCK_LENGTH\0"
    "LIST_CANNOT_BE_NULL\0"
    "MISSING_CLOSE_SQUARE_BRACKET\0"
    "MISSING_EQUAL_SIGN\0"
    "NO_CLOSE_BRACE\0"
    "UNABLE_TO_CREATE_NEW_SECTION\0"
    "VARIABLE_EXPANSION_TOO_LONG\0"
    "VARIABLE_HAS_NO_VALUE\0"
    "BAD_GENERATOR\0"
    "INVALID_PUBKEY\0"
    "MODULUS_TOO_LARGE\0"
    "NO_PRIVATE_VALUE\0"
    "UNKNOWN_HASH\0"
    "BAD_Q_VALUE\0"
    "BAD_VERSION\0"
    "INVALID_PARAMETERS\0"
    "MISSING_PARAMETERS\0"
    "NEED_NEW_SETUP_VALUES\0"
    "BIGNUM_OUT_OF_RANGE\0"
    "COORDINATES_OUT_OF_RANGE\0"
    "D2I_ECPKPARAMETERS_FAILURE\0"
    "EC_GROUP_NEW_BY_NAME_FAILURE\0"
    "GROUP2PKPARAMETERS_FAILURE\0"
    "GROUP_MISMATCH\0"
    "I2D_ECPKPARAMETERS_FAILURE\0"
    "INCOMPATIBLE_OBJECTS\0"
    "INVALID_COFACTOR\0"
    "INVALID_COMPRESSED_POINT\0"
    "INVALID_COMPRESSION_BIT\0"
    "INVALID_ENCODING\0"
    "INVALID_FIELD\0"
    "INVALID_FORM\0"
    "INVALID_GROUP_ORDER\0"
    "INVALID_PRIVATE_KEY\0"
    "INVALID_SCALAR\0"
    "MISSING_PRIVATE_KEY\0"
    "NON_NAMED_CURVE\0"
    "PKPARAMETERS2GROUP_FAILURE\0"
    "POINT_AT_INFINITY\0"
    "POINT_IS_NOT_ON_CURVE\0"
    "PUBLIC_KEY_VALIDATION_FAILED\0"
    "SLOT_FULL\0"
    "UNDEFINED_GENERATOR\0"
    "UNKNOWN_GROUP\0"
    "UNKNOWN_ORDER\0"
    "WRONG_CURVE_PARAMETERS\0"
    "WRONG_ORDER\0"
    "KDF_FAILED\0"
    "POINT_ARITHMETIC_FAILURE\0"
    "UNKNOWN_DIGEST_LENGTH\0"
    "BAD_SIGNATURE\0"
    "NOT_IMPLEMENTED\0"
    "RANDOM_NUMBER_GENERATION_FAILED\0"
    "OPERATION_NOT_SUPPORTED\0"
    "COMMAND_NOT_SUPPORTED\0"
    "DIFFERENT_KEY_TYPES\0"
    "DIFFERENT_PARAMETERS\0"
    "EMPTY_PSK\0"
    "EXPECTING_AN_EC_KEY_KEY\0"
    "EXPECTING_AN_RSA_KEY\0"
    "EXPECTING_A_DSA_KEY\0"
    "ILLEGAL_OR_UNSUPPORTED_PADDING_MODE\0"
    "INVALID_BUFFER_SIZE\0"
    "INVALID_DIGEST_LENGTH\0"
    "INVALID_DIGEST_TYPE\0"
    "INVALID_KEYBITS\0"
    "INVALID_MGF1_MD\0"
    "INVALID_PADDING_MODE\0"
    "INVALID_PEER_KEY\0"
    "INVALID_PSS_SALTLEN\0"
    "INVALID_SIGNATURE\0"
    "KEYS_NOT_SET\0"
    "MEMORY_LIMIT_EXCEEDED\0"
    "NOT_A_PRIVATE_KEY\0"
    "NOT_XOF_OR_INVALID_LENGTH\0"
    "NO_DEFAULT_DIGEST\0"
    "NO_KEY_SET\0"
    "NO_MDC2_SUPPORT\0"
    "NO_NID_FOR_CURVE\0"
    "NO_OPERATION_SET\0"
    "NO_PARAMETERS_SET\0"
    "OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE\0"
    "OPERATON_NOT_INITIALIZED\0"
    "UNKNOWN_PUBLIC_KEY_TYPE\0"
    "UNSUPPORTED_ALGORITHM\0"
    "OUTPUT_TOO_LARGE\0"
    "INVALID_OID_STRING\0"
    "UNKNOWN_NID\0"
    "NOT_BASIC_RESPONSE\0"
    "NO_RESPONSE_DATA\0"
    "BAD_BASE64_DECODE\0"
    "BAD_END_LINE\0"
    "BAD_IV_CHARS\0"
    "BAD_PASSWORD_READ\0"
    "CIPHER_IS_NULL\0"
    "ERROR_CONVERTING_PRIVATE_KEY\0"
    "NOT_DEK_INFO\0"
    "NOT_ENCRYPTED\0"
    "NOT_PROC_TYPE\0"
    "NO_START_LINE\0"
    "READ_KEY\0"
    "SHORT_HEADER\0"
    "UNSUPPORTED_CIPHER\0"
    "UNSUPPORTED_ENCRYPTION\0"
    "BAD_PKCS7_VERSION\0"
    "NOT_PKCS7_SIGNED_DATA\0"
    "NO_CERTIFICATES_INCLUDED\0"
    "NO_CRLS_INCLUDED\0"
    "BAD_ITERATION_COUNT\0"
    "BAD_PKCS12_DATA\0"
    "BAD_PKCS12_VERSION\0"
    "CIPHER_HAS_NO_OBJECT_IDENTIFIER\0"
    "CRYPT_ERROR\0"
    "ENCRYPT_ERROR\0"
    "ERROR_SETTING_CIPHER_PARAMS\0"
    "INCORRECT_PASSWORD\0"
    "INVALID_CHARACTERS\0"
    "KEYGEN_FAILURE\0"
    "KEY_GEN_ERROR\0"
    "METHOD_NOT_SUPPORTED\0"
    "MISSING_MAC\0"
    "MULTIPLE_PRIVATE_KEYS_IN_PKCS12\0"
    "PKCS12_PUBLIC_KEY_INTEGRITY_NOT_SUPPORTED\0"
    "PKCS12_TOO_DEEPLY_NESTED\0"
    "PRIVATE_KEY_DECODE_ERROR\0"
    "PRIVATE_KEY_ENCODE_ERROR\0"
    "UNKNOWN_ALGORITHM\0"
    "UNKNOWN_CIPHER\0"
    "UNKNOWN_CIPHER_ALGORITHM\0"
    "UNKNOWN_DIGEST\0"
    "UNSUPPORTED_KEYLENGTH\0"
    "UNSUPPORTED_KEY_DERIVATION_FUNCTION\0"
    "UNSUPPORTED_OPTIONS\0"
    "UNSUPPORTED_PRF\0"
    "UNSUPPORTED_PRIVATE_KEY_ALGORITHM\0"
    "UNSUPPORTED_SALT_TYPE\0"
    "BAD_E_VALUE\0"
    "BAD_FIXED_HEADER_DECRYPT\0"
    "BAD_PAD_BYTE_COUNT\0"
    "BAD_RSA_PARAMETERS\0"
    "BLOCK_TYPE_IS_NOT_01\0"
    "BLOCK_TYPE_IS_NOT_02\0"
    "BN_NOT_INITIALIZED\0"
    "CANNOT_RECOVER_MULTI_PRIME_KEY\0"
    "CRT_PARAMS_ALREADY_GIVEN\0"
    "CRT_VALUES_INCORRECT\0"
    "DATA_LEN_NOT_EQUAL_TO_MOD_LEN\0"
    "DATA_TOO_LARGE\0"
    "DATA_TOO_LARGE_FOR_KEY_SIZE\0"
    "DATA_TOO_LARGE_FOR_MODULUS\0"
    "DATA_TOO_SMALL\0"
    "DATA_TOO_SMALL_FOR_KEY_SIZE\0"
    "DIGEST_TOO_BIG_FOR_RSA_KEY\0"
    "D_E_NOT_CONGRUENT_TO_1\0"
    "D_OUT_OF_RANGE\0"
    "EMPTY_PUBLIC_KEY\0"
    "FIRST_OCTET_INVALID\0"
    "INCONSISTENT_SET_OF_CRT_VALUES\0"
    "INTERNAL_ERROR\0"
    "INVALID_MESSAGE_LENGTH\0"
    "KEY_SIZE_TOO_SMALL\0"
    "LAST_OCTET_INVALID\0"
    "MUST_HAVE_AT_LEAST_TWO_PRIMES\0"
    "NO_PUBLIC_EXPONENT\0"
    "NULL_BEFORE_BLOCK_MISSING\0"
    "N_NOT_EQUAL_P_Q\0"
    "OAEP_DECODING_ERROR\0"
    "ONLY_ONE_OF_P_Q_GIVEN\0"
    "OUTPUT_BUFFER_TOO_SMALL\0"
    "PADDING_CHECK_FAILED\0"
    "PKCS_DECODING_ERROR\0"
    "SLEN_CHECK_FAILED\0"
    "SLEN_RECOVERY_FAILED\0"
    "UNKNOWN_ALGORITHM_TYPE\0"
    "UNKNOWN_PADDING_TYPE\0"
    "VALUE_MISSING\0"
    "WRONG_SIGNATURE_LENGTH\0"
    "ALPN_MISMATCH_ON_EARLY_DATA\0"
    "ALPS_MISMATCH_ON_EARLY_DATA\0"
    "APPLICATION_DATA_INSTEAD_OF_HANDSHAKE\0"
    "APPLICATION_DATA_ON_SHUTDOWN\0"
    "APP_DATA_IN_HANDSHAKE\0"
    "ATTEMPT_TO_REUSE_SESSION_IN_DIFFERENT_CONTEXT\0"
    "BAD_ALERT\0"
    "BAD_CHANGE_CIPHER_SPEC\0"
    "BAD_DATA_RETURNED_BY_CALLBACK\0"
    "BAD_DH_P_LENGTH\0"
    "BAD_DIGEST_LENGTH\0"
    "BAD_ECC_CERT\0"
    "BAD_ECPOINT\0"
    "BAD_HANDSHAKE_RECORD\0"
    "BAD_HELLO_REQUEST\0"
    "BAD_LENGTH\0"
    "BAD_PACKET_LENGTH\0"
    "BAD_RSA_ENCRYPT\0"
    "BAD_SRTP_MKI_VALUE\0"
    "BAD_SRTP_PROTECTION_PROFILE_LIST\0"
    "BAD_SSL_FILETYPE\0"
    "BAD_WRITE_RETRY\0"
    "BIO_NOT_SET\0"
    "BLOCK_CIPHER_PAD_IS_WRONG\0"
    "CANNOT_HAVE_BOTH_PRIVKEY_AND_METHOD\0"
    "CANNOT_PARSE_LEAF_CERT\0"
    "CA_DN_LENGTH_MISMATCH\0"
    "CA_DN_TOO_LONG\0"
    "CCS_RECEIVED_EARLY\0"
    "CERTIFICATE_AND_PRIVATE_KEY_MISMATCH\0"
    "CERTIFICATE_VERIFY_FAILED\0"
    "CERT_CB_ERROR\0"
    "CERT_DECOMPRESSION_FAILED\0"
    "CERT_LENGTH_MISMATCH\0"
    "CHANNEL_ID_NOT_P256\0"
    "CHANNEL_ID_SIGNATURE_INVALID\0"
    "CIPHER_MISMATCH_ON_EARLY_DATA\0"
    "CIPHER_OR_HASH_UNAVAILABLE\0"
    "CLIENTHELLO_PARSE_FAILED\0"
    "CLIENTHELLO_TLSEXT\0"
    "CONNECTION_REJECTED\0"
    "CONNECTION_TYPE_NOT_SET\0"
    "COULD_NOT_PARSE_HINTS\0"
    "CUSTOM_EXTENSION_ERROR\0"
    "DATA_LENGTH_TOO_LONG\0"
    "DECRYPTION_FAILED\0"
    "DECRYPTION_FAILED_OR_BAD_RECORD_MAC\0"
    "DH_PUBLIC_VALUE_LENGTH_IS_WRONG\0"
    "DH_P_TOO_LONG\0"
    "DIGEST_CHECK_FAILED\0"
    "DOWNGRADE_DETECTED\0"
    "DTLS_MESSAGE_TOO_BIG\0"
    "DUPLICATE_EXTENSION\0"
    "DUPLICATE_KEY_SHARE\0"
    "DUPLICATE_SIGNATURE_ALGORITHM\0"
    "EARLY_DATA_NOT_IN_USE\0"
    "ECC_CERT_NOT_FOR_SIGNING\0"
    "ECH_SERVER_CONFIG_AND_PRIVATE_KEY_MISMATCH\0"
    "ECH_SERVER_CONFIG_UNSUPPORTED_EXTENSION\0"
    "ECH_SERVER_WOULD_HAVE_NO_RETRY_CONFIGS\0"
    "EMPTY_HELLO_RETRY_REQUEST\0"
    "EMS_STATE_INCONSISTENT\0"
    "ENCRYPTED_LENGTH_TOO_LONG\0"
    "ERROR_ADDING_EXTENSION\0"
    "ERROR_IN_RECEIVED_CIPHER_LIST\0"
    "ERROR_PARSING_EXTENSION\0"
    "EXCESSIVE_MESSAGE_SIZE\0"
    "EXCESS_HANDSHAKE_DATA\0"
    "EXTRA_DATA_IN_MESSAGE\0"
    "FRAGMENT_MISMATCH\0"
    "GOT_NEXT_PROTO_WITHOUT_EXTENSION\0"
    "HANDSHAKE_FAILURE_ON_CLIENT_HELLO\0"
    "HANDSHAKE_NOT_COMPLETE\0"
    "HTTPS_PROXY_REQUEST\0"
    "HTTP_REQUEST\0"
    "INAPPROPRIATE_FALLBACK\0"
    "INCONSISTENT_CLIENT_HELLO\0"
    "INVALID_ALPN_PROTOCOL\0"
    "INVALID_ALPN_PROTOCOL_LIST\0"
    "INVALID_CLIENT_HELLO_INNER\0"
    "INVALID_COMMAND\0"
    "INVALID_COMPRESSION_LIST\0"
    "INVALID_DELEGATED_CREDENTIAL\0"
    "INVALID_MESSAGE\0"
    "INVALID_OUTER_RECORD_TYPE\0"
    "INVALID_SCT_LIST\0"
    "INVALID_SIGNATURE_ALGORITHM\0"
    "INVALID_SSL_SESSION\0"
    "INVALID_TICKET_KEYS_LENGTH\0"
    "KEY_USAGE_BIT_INCORRECT\0"
    "LENGTH_MISMATCH\0"
    "MISSING_EXTENSION\0"
    "MISSING_KEY_SHARE\0"
    "MISSING_RSA_CERTIFICATE\0"
    "MISSING_TMP_DH_KEY\0"
    "MISSING_TMP_ECDH_KEY\0"
    "MIXED_SPECIAL_OPERATOR_WITH_GROUPS\0"
    "MTU_TOO_SMALL\0"
    "NEGOTIATED_ALPS_WITHOUT_ALPN\0"
    "NEGOTIATED_BOTH_NPN_AND_ALPN\0"
    "NEGOTIATED_TB_WITHOUT_EMS_OR_RI\0"
    "NESTED_GROUP\0"
    "NO_APPLICATION_PROTOCOL\0"
    "NO_CERTIFICATES_RETURNED\0"
    "NO_CERTIFICATE_ASSIGNED\0"
    "NO_CERTIFICATE_SET\0"
    "NO_CIPHERS_AVAILABLE\0"
    "NO_CIPHERS_PASSED\0"
    "NO_CIPHERS_SPECIFIED\0"
    "NO_CIPHER_MATCH\0"
    "NO_COMMON_SIGNATURE_ALGORITHMS\0"
    "NO_COMPRESSION_SPECIFIED\0"
    "NO_GROUPS_SPECIFIED\0"
    "NO_METHOD_SPECIFIED\0"
    "NO_P256_SUPPORT\0"
    "NO_PRIVATE_KEY_ASSIGNED\0"
    "NO_RENEGOTIATION\0"
    "NO_REQUIRED_DIGEST\0"
    "NO_SHARED_CIPHER\0"
    "NO_SHARED_GROUP\0"
    "NO_SUPPORTED_VERSIONS_ENABLED\0"
    "NULL_SSL_CTX\0"
    "NULL_SSL_METHOD_PASSED\0"
    "OCSP_CB_ERROR\0"
    "OLD_SESSION_CIPHER_NOT_RETURNED\0"
    "OLD_SESSION_PRF_HASH_MISMATCH\0"
    "OLD_SESSION_VERSION_NOT_RETURNED\0"
    "PARSE_TLSEXT\0"
    "PATH_TOO_LONG\0"
    "PEER_DID_NOT_RETURN_A_CERTIFICATE\0"
    "PEER_ERROR_UNSUPPORTED_CERTIFICATE_TYPE\0"
    "PRE_SHARED_KEY_MUST_BE_LAST\0"
    "PRIVATE_KEY_OPERATION_FAILED\0"
    "PROTOCOL_IS_SHUTDOWN\0"
    "PSK_IDENTITY_BINDER_COUNT_MISMATCH\0"
    "PSK_IDENTITY_NOT_FOUND\0"
    "PSK_NO_CLIENT_CB\0"
    "PSK_NO_SERVER_CB\0"
    "QUIC_INTERNAL_ERROR\0"
    "QUIC_TRANSPORT_PARAMETERS_MISCONFIGURED\0"
    "READ_TIMEOUT_EXPIRED\0"
    "RECORD_LENGTH_MISMATCH\0"
    "RECORD_TOO_LARGE\0"
    "RENEGOTIATION_EMS_MISMATCH\0"
    "RENEGOTIATION_ENCODING_ERR\0"
    "RENEGOTIATION_MISMATCH\0"
    "REQUIRED_CIPHER_MISSING\0"
    "RESUMED_EMS_SESSION_WITHOUT_EMS_EXTENSION\0"
    "RESUMED_NON_EMS_SESSION_WITH_EMS_EXTENSION\0"
    "SCSV_RECEIVED_WHEN_RENEGOTIATING\0"
    "SECOND_SERVERHELLO_VERSION_MISMATCH\0"
    "SERVERHELLO_TLSEXT\0"
    "SERVER_CERT_CHANGED\0"
    "SERVER_ECHOED_INVALID_SESSION_ID\0"
    "SESSION_ID_CONTEXT_UNINITIALIZED\0"
    "SESSION_MAY_NOT_BE_CREATED\0"
    "SHUTDOWN_WHILE_IN_INIT\0"
    "SIGNATURE_ALGORITHMS_EXTENSION_SENT_BY_SERVER\0"
    "SRTP_COULD_NOT_ALLOCATE_PROFILES\0"
    "SRTP_UNKNOWN_PROTECTION_PROFILE\0"
    "SSL3_EXT_INVALID_SERVERNAME\0"
    "SSLV3_ALERT_BAD_CERTIFICATE\0"
    "SSLV3_ALERT_BAD_RECORD_MAC\0"
    "SSLV3_ALERT_CERTIFICATE_EXPIRED\0"
    "SSLV3_ALERT_CERTIFICATE_REVOKED\0"
    "SSLV3_ALERT_CERTIFICATE_UNKNOWN\0"
    "SSLV3_ALERT_CLOSE_NOTIFY\0"
    "SSLV3_ALERT_DECOMPRESSION_FAILURE\0"
    "SSLV3_ALERT_HANDSHAKE_FAILURE\0"
    "SSLV3_ALERT_ILLEGAL_PARAMETER\0"
    "SSLV3_ALERT_NO_CERTIFICATE\0"
    "SSLV3_ALERT_UNEXPECTED_MESSAGE\0"
    "SSLV3_ALERT_UNSUPPORTED_CERTIFICATE\0"
    "SSL_CTX_HAS_NO_DEFAULT_SSL_VERSION\0"
    "SSL_HANDSHAKE_FAILURE\0"
    "SSL_SESSION_ID_CONTEXT_TOO_LONG\0"
    "SSL_SESSION_ID_TOO_LONG\0"
    "TICKET_ENCRYPTION_FAILED\0"
    "TLS13_DOWNGRADE\0"
    "TLSV1_ALERT_ACCESS_DENIED\0"
    "TLSV1_ALERT_BAD_CERTIFICATE_HASH_VALUE\0"
    "TLSV1_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE\0"
    "TLSV1_ALERT_CERTIFICATE_REQUIRED\0"
    "TLSV1_ALERT_CERTIFICATE_UNOBTAINABLE\0"
    "TLSV1_ALERT_DECODE_ERROR\0"
    "TLSV1_ALERT_DECRYPTION_FAILED\0"
    "TLSV1_ALERT_DECRYPT_ERROR\0"
    "TLSV1_ALERT_EXPORT_RESTRICTION\0"
    "TLSV1_ALERT_INAPPROPRIATE_FALLBACK\0"
    "TLSV1_ALERT_INSUFFICIENT_SECURITY\0"
    "TLSV1_ALERT_INTERNAL_ERROR\0"
    "TLSV1_ALERT_NO_APPLICATION_PROTOCOL\0"
    "TLSV1_ALERT_NO_RENEGOTIATION\0"
    "TLSV1_ALERT_PROTOCOL_VERSION\0"
    "TLSV1_ALERT_RECORD_OVERFLOW\0"
    "TLSV1_ALERT_UNKNOWN_CA\0"
    "TLSV1_ALERT_UNKNOWN_PSK_IDENTITY\0"
    "TLSV1_ALERT_UNRECOGNIZED_NAME\0"
    "TLSV1_ALERT_UNSUPPORTED_EXTENSION\0"
    "TLSV1_ALERT_USER_CANCELLED\0"
    "TLS_PEER_DID_NOT_RESPOND_WITH_CERTIFICATE_LIST\0"
    "TLS_RSA_ENCRYPTED_VALUE_LENGTH_IS_WRONG\0"
    "TOO_MANY_EMPTY_FRAGMENTS\0"
    "TOO_MANY_KEY_UPDATES\0"
    "TOO_MANY_WARNING_ALERTS\0"
    "TOO_MUCH_READ_EARLY_DATA\0"
    "TOO_MUCH_SKIPPED_EARLY_DATA\0"
    "UNABLE_TO_FIND_ECDH_PARAMETERS\0"
    "UNCOMPRESSED_CERT_TOO_LARGE\0"
    "UNEXPECTED_COMPATIBILITY_MODE\0"
    "UNEXPECTED_EXTENSION\0"
    "UNEXPECTED_EXTENSION_ON_EARLY_DATA\0"
    "UNEXPECTED_MESSAGE\0"
    "UNEXPECTED_OPERATOR_IN_GROUP\0"
    "UNEXPECTED_RECORD\0"
    "UNKNOWN_ALERT_TYPE\0"
    "UNKNOWN_CERTIFICATE_TYPE\0"
    "UNKNOWN_CERT_COMPRESSION_ALG\0"
    "UNKNOWN_CIPHER_RETURNED\0"
    "UNKNOWN_CIPHER_TYPE\0"
    "UNKNOWN_KEY_EXCHANGE_TYPE\0"
    "UNKNOWN_PROTOCOL\0"
    "UNKNOWN_SSL_VERSION\0"
    "UNKNOWN_STATE\0"
    "UNSAFE_LEGACY_RENEGOTIATION_DISABLED\0"
    "UNSUPPORTED_COMPRESSION_ALGORITHM\0"
    "UNSUPPORTED_ECH_SERVER_CONFIG\0"
    "UNSUPPORTED_ELLIPTIC_CURVE\0"
    "UNSUPPORTED_PROTOCOL\0"
    "UNSUPPORTED_PROTOCOL_FOR_CUSTOM_KEY\0"
    "WRONG_CERTIFICATE_TYPE\0"
    "WRONG_CIPHER_RETURNED\0"
    "WRONG_CURVE\0"
    "WRONG_ENCRYPTION_LEVEL_RECEIVED\0"
    "WRONG_MESSAGE_TYPE\0"
    "WRONG_SIGNATURE_TYPE\0"
    "WRONG_SSL_VERSION\0"
    "WRONG_VERSION_NUMBER\0"
    "WRONG_VERSION_ON_EARLY_DATA\0"
    "X509_LIB\0"
    "X509_VERIFICATION_SETUP_PROBLEMS\0"
    "BAD_VALIDITY_CHECK\0"
    "DECODE_FAILURE\0"
    "INVALID_KEY_ID\0"
    "INVALID_METADATA\0"
    "INVALID_METADATA_KEY\0"
    "INVALID_PROOF\0"
    "INVALID_TOKEN\0"
    "NO_KEYS_CONFIGURED\0"
    "NO_SRR_KEY_CONFIGURED\0"
    "OVER_BATCHSIZE\0"
    "SRR_SIGNATURE_ERROR\0"
    "TOO_MANY_KEYS\0"
    "AKID_MISMATCH\0"
    "BAD_X509_FILETYPE\0"
    "BASE64_DECODE_ERROR\0"
    "CANT_CHECK_DH_KEY\0"
    "CERT_ALREADY_IN_HASH_TABLE\0"
    "CRL_ALREADY_DELTA\0"
    "CRL_VERIFY_FAILURE\0"
    "DELTA_CRL_WITHOUT_CRL_NUMBER\0"
    "IDP_MISMATCH\0"
    "INVALID_DIRECTORY\0"
    "INVALID_FIELD_FOR_VERSION\0"
    "INVALID_FIELD_NAME\0"
    "INVALID_PARAMETER\0"
    "INVALID_PSS_PARAMETERS\0"
    "INVALID_TRUST\0"
    "INVALID_VERSION\0"
    "ISSUER_MISMATCH\0"
    "KEY_TYPE_MISMATCH\0"
    "KEY_VALUES_MISMATCH\0"
    "LOADING_CERT_DIR\0"
    "LOADING_DEFAULTS\0"
    "NAME_TOO_LONG\0"
    "NEWER_CRL_NOT_NEWER\0"
    "NO_CERT_SET_FOR_US_TO_VERIFY\0"
    "NO_CRL_NUMBER\0"
    "PUBLIC_KEY_DECODE_ERROR\0"
    "PUBLIC_KEY_ENCODE_ERROR\0"
    "SHOULD_RETRY\0"
    "SIGNATURE_ALGORITHM_MISMATCH\0"
    "UNKNOWN_KEY_TYPE\0"
    "UNKNOWN_PURPOSE_ID\0"
    "UNKNOWN_TRUST_ID\0"
    "WRONG_LOOKUP_TYPE\0"
    "BAD_IP_ADDRESS\0"
    "BAD_OBJECT\0"
    "BN_DEC2BN_ERROR\0"
    "BN_TO_ASN1_INTEGER_ERROR\0"
    "CANNOT_FIND_FREE_FUNCTION\0"
    "DIRNAME_ERROR\0"
    "DISTPOINT_ALREADY_SET\0"
    "DUPLICATE_ZONE_ID\0"
    "ERROR_CONVERTING_ZONE\0"
    "ERROR_CREATING_EXTENSION\0"
    "ERROR_IN_EXTENSION\0"
    "EXPECTED_A_SECTION_NAME\0"
    "EXTENSION_EXISTS\0"
    "EXTENSION_NAME_ERROR\0"
    "EXTENSION_NOT_FOUND\0"
    "EXTENSION_SETTING_NOT_SUPPORTED\0"
    "EXTENSION_VALUE_ERROR\0"
    "ILLEGAL_EMPTY_EXTENSION\0"
    "ILLEGAL_HEX_DIGIT\0"
    "INCORRECT_POLICY_SYNTAX_TAG\0"
    "INVALID_BOOLEAN_STRING\0"
    "INVALID_EXTENSION_STRING\0"
    "INVALID_MULTIPLE_RDNS\0"
    "INVALID_NAME\0"
    "INVALID_NULL_ARGUMENT\0"
    "INVALID_NULL_NAME\0"
    "INVALID_NULL_VALUE\0"
    "INVALID_NUMBERS\0"
    "INVALID_OBJECT_IDENTIFIER\0"
    "INVALID_OPTION\0"
    "INVALID_POLICY_IDENTIFIER\0"
    "INVALID_PROXY_POLICY_SETTING\0"
    "INVALID_PURPOSE\0"
    "INVALID_SECTION\0"
    "INVALID_SYNTAX\0"
    "ISSUER_DECODE_ERROR\0"
    "NEED_ORGANIZATION_AND_NUMBERS\0"
    "NO_CONFIG_DATABASE\0"
    "NO_ISSUER_CERTIFICATE\0"
    "NO_ISSUER_DETAILS\0"
    "NO_POLICY_IDENTIFIER\0"
    "NO_PROXY_CERT_POLICY_LANGUAGE_DEFINED\0"
    "NO_PUBLIC_KEY\0"
    "NO_SUBJECT_DETAILS\0"
    "ODD_NUMBER_OF_DIGITS\0"
    "OPERATION_NOT_DEFINED\0"
    "OTHERNAME_ERROR\0"
    "POLICY_LANGUAGE_ALREADY_DEFINED\0"
    "POLICY_PATH_LENGTH\0"
    "POLICY_PATH_LENGTH_ALREADY_DEFINED\0"
    "POLICY_WHEN_PROXY_LANGUAGE_REQUIRES_NO_POLICY\0"
    "SECTION_NOT_FOUND\0"
    "UNABLE_TO_GET_ISSUER_DETAILS\0"
    "UNABLE_TO_GET_ISSUER_KEYID\0"
    "UNKNOWN_BIT_STRING_ARGUMENT\0"
    "UNKNOWN_EXTENSION\0"
    "UNKNOWN_EXTENSION_NAME\0"
    "UNKNOWN_OPTION\0"
    "UNSUPPORTED_OPTION\0"
    "USER_TOO_LONG\0"
    "";
