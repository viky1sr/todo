#![allow(dead_code)]

use hex_literal::hex;

// Test vectors transcribed verbatim from RFC 8452 Appendix C
// (C.1 AEAD_AES_128_GCM_SIV, C.2 AEAD_AES_256_GCM_SIV, C.3 Counter Wrap Tests).
// Generated mechanically from https://www.rfc-editor.org/rfc/rfc8452.txt.

pub struct Rfc8452Vector {
    pub section: &'static str,
    pub plaintext: &'static [u8],
    pub aad: &'static [u8],
    pub key: &'static [u8],
    pub nonce: [u8; 12],
    pub auth_key: [u8; 16],
    pub polyval_input: &'static [u8],
    pub polyval_result: [u8; 16],
    pub tag: [u8; 16],
    /// Ciphertext || tag.
    pub result: &'static [u8],
}

pub const RFC8452_VECTORS: &[Rfc8452Vector] = &[
    Rfc8452Vector {
        section: "C.1",
        plaintext: &hex!(""),
        aad: &hex!(""),
        key: &hex!("01000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("d9b360279694941ac5dbc6987ada7377"),
        polyval_input: &hex!("00000000000000000000000000000000"),
        polyval_result: hex!("00000000000000000000000000000000"),
        tag: hex!("dc20e2d83f25705bb49e439eca56de25"),
        result: &hex!("dc20e2d83f25705bb49e439eca56de25"),
    },
    Rfc8452Vector {
        section: "C.1",
        plaintext: &hex!("0100000000000000"),
        aad: &hex!(""),
        key: &hex!("01000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("d9b360279694941ac5dbc6987ada7377"),
        polyval_input: &hex!("0100000000000000000000000000000000000000000000004000000000000000"),
        polyval_result: hex!("eb93b7740962c5e49d2a90a7dc5cec74"),
        tag: hex!("578782fff6013b815b287c22493a364c"),
        result: &hex!("b5d839330ac7b786578782fff6013b815b287c22493a364c"),
    },
    Rfc8452Vector {
        section: "C.1",
        plaintext: &hex!("010000000000000000000000"),
        aad: &hex!(""),
        key: &hex!("01000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("d9b360279694941ac5dbc6987ada7377"),
        polyval_input: &hex!("0100000000000000000000000000000000000000000000006000000000000000"),
        polyval_result: hex!("48eb6c6c5a2dbe4a1dde508fee06361b"),
        tag: hex!("a4978db357391a0bc4fdec8b0d106639"),
        result: &hex!("7323ea61d05932260047d942a4978db357391a0bc4fdec8b0d106639"),
    },
    Rfc8452Vector {
        section: "C.1",
        plaintext: &hex!("01000000000000000000000000000000"),
        aad: &hex!(""),
        key: &hex!("01000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("d9b360279694941ac5dbc6987ada7377"),
        polyval_input: &hex!("0100000000000000000000000000000000000000000000008000000000000000"),
        polyval_result: hex!("20806c26e3c1de019e111255708031d6"),
        tag: hex!("303aaf90f6fe21199c6068577437a0c4"),
        result: &hex!("743f7c8077ab25f8624e2e948579cf77303aaf90f6fe21199c6068577437a0c4"),
    },
    Rfc8452Vector {
        section: "C.1",
        plaintext: &hex!("0100000000000000000000000000000002000000000000000000000000000000"),
        aad: &hex!(""),
        key: &hex!("01000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("d9b360279694941ac5dbc6987ada7377"),
        polyval_input: &hex!(
            "010000000000000000000000000000000200000000000000000000000000000000000000000000000001000000000000"
        ),
        polyval_result: hex!("ce6edc9a50b36d9a98986bbf6a261c3b"),
        tag: hex!("1a8e45dcd4578c667cd86847bf6155ff"),
        result: &hex!(
            "84e07e62ba83a6585417245d7ec413a9fe427d6315c09b57ce45f2e3936a94451a8e45dcd4578c667cd86847bf6155ff"
        ),
    },
    Rfc8452Vector {
        section: "C.1",
        plaintext: &hex!(
            "010000000000000000000000000000000200000000000000000000000000000003000000000000000000000000000000"
        ),
        aad: &hex!(""),
        key: &hex!("01000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("d9b360279694941ac5dbc6987ada7377"),
        polyval_input: &hex!(
            "01000000000000000000000000000000020000000000000000000000000000000300000000000000000000000000000000000000000000008001000000000000"
        ),
        polyval_result: hex!("81388746bc22d26b2abc3dcb15754222"),
        tag: hex!("5e6e311dbf395d35b0fe39c2714388f8"),
        result: &hex!(
            "3fd24ce1f5a67b75bf2351f181a475c7b800a5b4d3dcf70106b1eea82fa1d64df42bf7226122fa92e17a40eeaac1201b5e6e311dbf395d35b0fe39c2714388f8"
        ),
    },
    Rfc8452Vector {
        section: "C.1",
        plaintext: &hex!(
            "01000000000000000000000000000000020000000000000000000000000000000300000000000000000000000000000004000000000000000000000000000000"
        ),
        aad: &hex!(""),
        key: &hex!("01000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("d9b360279694941ac5dbc6987ada7377"),
        polyval_input: &hex!(
            "0100000000000000000000000000000002000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000000000000000000000002000000000000"
        ),
        polyval_result: hex!("1e39b6d3344d348f6044f89935d1cf78"),
        tag: hex!("8a263dd317aa88d56bdf3936dba75bb8"),
        result: &hex!(
            "2433668f1058190f6d43e360f4f35cd8e475127cfca7028ea8ab5c20f7ab2af02516a2bdcbc08d521be37ff28c152bba36697f25b4cd169c6590d1dd39566d3f8a263dd317aa88d56bdf3936dba75bb8"
        ),
    },
    Rfc8452Vector {
        section: "C.1",
        plaintext: &hex!("0200000000000000"),
        aad: &hex!("01"),
        key: &hex!("01000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("d9b360279694941ac5dbc6987ada7377"),
        polyval_input: &hex!(
            "010000000000000000000000000000000200000000000000000000000000000008000000000000004000000000000000"
        ),
        polyval_result: hex!("b26781e7e2c1376f96bec195f3709b2a"),
        tag: hex!("3b0a1a2560969cdf790d99759abd1508"),
        result: &hex!("1e6daba35669f4273b0a1a2560969cdf790d99759abd1508"),
    },
    Rfc8452Vector {
        section: "C.1",
        plaintext: &hex!("020000000000000000000000"),
        aad: &hex!("01"),
        key: &hex!("01000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("d9b360279694941ac5dbc6987ada7377"),
        polyval_input: &hex!(
            "010000000000000000000000000000000200000000000000000000000000000008000000000000006000000000000000"
        ),
        polyval_result: hex!("111f5affb18e4cc1164a01bdc12a4145"),
        tag: hex!("08299c5102745aaa3a0c469fad9e075a"),
        result: &hex!("296c7889fd99f41917f4462008299c5102745aaa3a0c469fad9e075a"),
    },
    Rfc8452Vector {
        section: "C.1",
        plaintext: &hex!("02000000000000000000000000000000"),
        aad: &hex!("01"),
        key: &hex!("01000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("d9b360279694941ac5dbc6987ada7377"),
        polyval_input: &hex!(
            "010000000000000000000000000000000200000000000000000000000000000008000000000000008000000000000000"
        ),
        polyval_result: hex!("79745ab508622c8a958543675fac4688"),
        tag: hex!("8f8936ec039e4e4bb97ebd8c4457441f"),
        result: &hex!("e2b0c5da79a901c1745f700525cb335b8f8936ec039e4e4bb97ebd8c4457441f"),
    },
    Rfc8452Vector {
        section: "C.1",
        plaintext: &hex!("0200000000000000000000000000000003000000000000000000000000000000"),
        aad: &hex!("01"),
        key: &hex!("01000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("d9b360279694941ac5dbc6987ada7377"),
        polyval_input: &hex!(
            "01000000000000000000000000000000020000000000000000000000000000000300000000000000000000000000000008000000000000000001000000000000"
        ),
        polyval_result: hex!("2ce7daaf7c89490822051255b12eca6b"),
        tag: hex!("e6af6a7f87287da059a71684ed3498e1"),
        result: &hex!(
            "620048ef3c1e73e57e02bb8562c416a319e73e4caac8e96a1ecb2933145a1d71e6af6a7f87287da059a71684ed3498e1"
        ),
    },
    Rfc8452Vector {
        section: "C.1",
        plaintext: &hex!(
            "020000000000000000000000000000000300000000000000000000000000000004000000000000000000000000000000"
        ),
        aad: &hex!("01"),
        key: &hex!("01000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("d9b360279694941ac5dbc6987ada7377"),
        polyval_input: &hex!(
            "0100000000000000000000000000000002000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000008000000000000008001000000000000"
        ),
        polyval_result: hex!("9ca987715d69c1786711dfcd22f830fc"),
        tag: hex!("6a8cc3865f76897c2e4b245cf31c51f2"),
        result: &hex!(
            "50c8303ea93925d64090d07bd109dfd9515a5a33431019c17d93465999a8b0053201d723120a8562b838cdff25bf9d1e6a8cc3865f76897c2e4b245cf31c51f2"
        ),
    },
    Rfc8452Vector {
        section: "C.1",
        plaintext: &hex!(
            "02000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000005000000000000000000000000000000"
        ),
        aad: &hex!("01"),
        key: &hex!("01000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("d9b360279694941ac5dbc6987ada7377"),
        polyval_input: &hex!(
            "010000000000000000000000000000000200000000000000000000000000000003000000000000000000000000000000040000000000000000000000000000000500000000000000000000000000000008000000000000000002000000000000"
        ),
        polyval_result: hex!("ffcd05d5770f34ad9267f0a59994b15a"),
        tag: hex!("cdc46ae475563de037001ef84ae21744"),
        result: &hex!(
            "2f5c64059db55ee0fb847ed513003746aca4e61c711b5de2e7a77ffd02da42feec601910d3467bb8b36ebbaebce5fba30d36c95f48a3e7980f0e7ac299332a80cdc46ae475563de037001ef84ae21744"
        ),
    },
    Rfc8452Vector {
        section: "C.1",
        plaintext: &hex!("02000000"),
        aad: &hex!("010000000000000000000000"),
        key: &hex!("01000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("d9b360279694941ac5dbc6987ada7377"),
        polyval_input: &hex!(
            "010000000000000000000000000000000200000000000000000000000000000060000000000000002000000000000000"
        ),
        polyval_result: hex!("f6ce9d3dcd68a2fd603c7ecc18fb9918"),
        tag: hex!("07eb1f84fb28f8cb73de8e99e2f48a14"),
        result: &hex!("a8fe3e8707eb1f84fb28f8cb73de8e99e2f48a14"),
    },
    Rfc8452Vector {
        section: "C.1",
        plaintext: &hex!("0300000000000000000000000000000004000000"),
        aad: &hex!("010000000000000000000000000000000200"),
        key: &hex!("01000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("d9b360279694941ac5dbc6987ada7377"),
        polyval_input: &hex!(
            "010000000000000000000000000000000200000000000000000000000000000003000000000000000000000000000000040000000000000000000000000000009000000000000000a000000000000000"
        ),
        polyval_result: hex!("4781d492cb8f926c504caa36f61008fe"),
        tag: hex!("24afc9805e976f451e6d87f6fe106514"),
        result: &hex!("6bb0fecf5ded9b77f902c7d5da236a4391dd029724afc9805e976f451e6d87f6fe106514"),
    },
    Rfc8452Vector {
        section: "C.1",
        plaintext: &hex!("030000000000000000000000000000000400"),
        aad: &hex!("0100000000000000000000000000000002000000"),
        key: &hex!("01000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("d9b360279694941ac5dbc6987ada7377"),
        polyval_input: &hex!(
            "01000000000000000000000000000000020000000000000000000000000000000300000000000000000000000000000004000000000000000000000000000000a0000000000000009000000000000000"
        ),
        polyval_result: hex!("75cbc23a1a10e348aeb8e384b5cc79fd"),
        tag: hex!("bff9b2ef00fb47920cc72a0c0f13b9fd"),
        result: &hex!("44d0aaf6fb2f1f34add5e8064e83e12a2adabff9b2ef00fb47920cc72a0c0f13b9fd"),
    },
    Rfc8452Vector {
        section: "C.1",
        plaintext: &hex!(""),
        aad: &hex!(""),
        key: &hex!("e66021d5eb8e4f4066d4adb9c33560e4"),
        nonce: hex!("f46e44bb3da0015c94f70887"),
        auth_key: hex!("036ee1fe2d7926af68898095e54e7b3c"),
        polyval_input: &hex!("00000000000000000000000000000000"),
        polyval_result: hex!("00000000000000000000000000000000"),
        tag: hex!("a4194b79071b01a87d65f706e3949578"),
        result: &hex!("a4194b79071b01a87d65f706e3949578"),
    },
    Rfc8452Vector {
        section: "C.1",
        plaintext: &hex!("7a806c"),
        aad: &hex!("46bb91c3c5"),
        key: &hex!("36864200e0eaf5284d884a0e77d31646"),
        nonce: hex!("bae8e37fc83441b16034566b"),
        auth_key: hex!("3e28de1120b2981a0155795ca2812af6"),
        polyval_input: &hex!(
            "46bb91c3c500000000000000000000007a806c0000000000000000000000000028000000000000001800000000000000"
        ),
        polyval_result: hex!("43d9a745511dcfa21b96dd606f1d5720"),
        tag: hex!("711bd85bc1e4d3e0a462e074eea428a8"),
        result: &hex!("af60eb711bd85bc1e4d3e0a462e074eea428a8"),
    },
    Rfc8452Vector {
        section: "C.1",
        plaintext: &hex!("bdc66f146545"),
        aad: &hex!("fc880c94a95198874296"),
        key: &hex!("aedb64a6c590bc84d1a5e269e4b47801"),
        nonce: hex!("afc0577e34699b9e671fdd4f"),
        auth_key: hex!("43b8de9cea62330d15cccfc84a33e8c8"),
        polyval_input: &hex!(
            "fc880c94a95198874296000000000000bdc66f1465450000000000000000000050000000000000003000000000000000"
        ),
        polyval_result: hex!("26498e0d2b1ef004e808c458e8f2f515"),
        tag: hex!("d6a9c45545cfc11f03ad743dba20f966"),
        result: &hex!("bb93a3e34d3cd6a9c45545cfc11f03ad743dba20f966"),
    },
    Rfc8452Vector {
        section: "C.1",
        plaintext: &hex!("1177441f195495860f"),
        aad: &hex!("046787f3ea22c127aaf195d1894728"),
        key: &hex!("d5cc1fd161320b6920ce07787f86743b"),
        nonce: hex!("275d1ab32f6d1f0434d8848c"),
        auth_key: hex!("8a51df64d93eaf667c2c09bd454ce5c5"),
        polyval_input: &hex!(
            "046787f3ea22c127aaf195d1894728001177441f195495860f0000000000000078000000000000004800000000000000"
        ),
        polyval_result: hex!("63a3451c0b23345ad02bba59956517cf"),
        tag: hex!("1d02fd0cd174c84fc5dae2f60f52fd2b"),
        result: &hex!("4f37281f7ad12949d01d02fd0cd174c84fc5dae2f60f52fd2b"),
    },
    Rfc8452Vector {
        section: "C.1",
        plaintext: &hex!("9f572c614b4745914474e7c7"),
        aad: &hex!("c9882e5386fd9f92ec489c8fde2be2cf97e74e93"),
        key: &hex!("b3fed1473c528b8426a582995929a149"),
        nonce: hex!("9e9ad8780c8d63d0ab4149c0"),
        auth_key: hex!("22f50707a95dd416df069d670cb775e8"),
        polyval_input: &hex!(
            "c9882e5386fd9f92ec489c8fde2be2cf97e74e930000000000000000000000009f572c614b4745914474e7c700000000a0000000000000006000000000000000"
        ),
        polyval_result: hex!("0cca0423fba9d77fe7e2e6963b08cdd0"),
        tag: hex!("c1dc2f871fb7561da1286e655e24b7b0"),
        result: &hex!("f54673c5ddf710c745641c8bc1dc2f871fb7561da1286e655e24b7b0"),
    },
    Rfc8452Vector {
        section: "C.1",
        plaintext: &hex!("0d8c8451178082355c9e940fea2f58"),
        aad: &hex!("2950a70d5a1db2316fd568378da107b52b0da55210cc1c1b0a"),
        key: &hex!("2d4ed87da44102952ef94b02b805249b"),
        nonce: hex!("ac80e6f61455bfac8308a2d4"),
        auth_key: hex!("0b00a29a83e7e95b92e3a0783b29f140"),
        polyval_input: &hex!(
            "2950a70d5a1db2316fd568378da107b52b0da55210cc1c1b0a000000000000000d8c8451178082355c9e940fea2f5800c8000000000000007800000000000000"
        ),
        polyval_result: hex!("1086ef25247aa41009bbc40871d9b350"),
        tag: hex!("83b3449b9f39552de99dc214a1190b0b"),
        result: &hex!("c9ff545e07b88a015f05b274540aa183b3449b9f39552de99dc214a1190b0b"),
    },
    Rfc8452Vector {
        section: "C.1",
        plaintext: &hex!("6b3db4da3d57aa94842b9803a96e07fb6de7"),
        aad: &hex!("1860f762ebfbd08284e421702de0de18baa9c9596291b08466f37de21c7f"),
        key: &hex!("bde3b2f204d1e9f8b06bc47f9745b3d1"),
        nonce: hex!("ae06556fb6aa7890bebc18fe"),
        auth_key: hex!("21c874a8bad3603d1c3e8784df5b3f9f"),
        polyval_input: &hex!(
            "1860f762ebfbd08284e421702de0de18baa9c9596291b08466f37de21c7f00006b3db4da3d57aa94842b9803a96e07fb6de70000000000000000000000000000f0000000000000009000000000000000"
        ),
        polyval_result: hex!("55462a5afa0da8d646481e049ef9c764"),
        tag: hex!("3e377094f04709f64d7b985310a4db84"),
        result: &hex!("6298b296e24e8cc35dce0bed484b7f30d5803e377094f04709f64d7b985310a4db84"),
    },
    Rfc8452Vector {
        section: "C.1",
        plaintext: &hex!("e42a3c02c25b64869e146d7b233987bddfc240871d"),
        aad: &hex!("7576f7028ec6eb5ea7e298342a94d4b202b370ef9768ec6561c4fe6b7e7296fa859c21"),
        key: &hex!("f901cfe8a69615a93fdf7a98cad48179"),
        nonce: hex!("6245709fb18853f68d833640"),
        auth_key: hex!("3724f55f1d22ac0ab830da0b6a995d74"),
        polyval_input: &hex!(
            "7576f7028ec6eb5ea7e298342a94d4b202b370ef9768ec6561c4fe6b7e7296fa859c2100000000000000000000000000e42a3c02c25b64869e146d7b233987bddfc240871d00000000000000000000001801000000000000a800000000000000"
        ),
        polyval_result: hex!("4cbba090f03f7d1188ea55749fa6c7bd"),
        tag: hex!("2d15506c84a9edd65e13e9d24a2a6e70"),
        result: &hex!("391cc328d484a4f46406181bcd62efd9b3ee197d052d15506c84a9edd65e13e9d24a2a6e70"),
    },
    Rfc8452Vector {
        section: "C.2",
        plaintext: &hex!(""),
        aad: &hex!(""),
        key: &hex!("0100000000000000000000000000000000000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("b5d3c529dfafac43136d2d11be284d7f"),
        polyval_input: &hex!("00000000000000000000000000000000"),
        polyval_result: hex!("00000000000000000000000000000000"),
        tag: hex!("07f5f4169bbf55a8400cd47ea6fd400f"),
        result: &hex!("07f5f4169bbf55a8400cd47ea6fd400f"),
    },
    Rfc8452Vector {
        section: "C.2",
        plaintext: &hex!("0100000000000000"),
        aad: &hex!(""),
        key: &hex!("0100000000000000000000000000000000000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("b5d3c529dfafac43136d2d11be284d7f"),
        polyval_input: &hex!("0100000000000000000000000000000000000000000000004000000000000000"),
        polyval_result: hex!("05230f62f0eac8aa14fe4d646b59cd41"),
        tag: hex!("843122130f7364b761e0b97427e3df28"),
        result: &hex!("c2ef328e5c71c83b843122130f7364b761e0b97427e3df28"),
    },
    Rfc8452Vector {
        section: "C.2",
        plaintext: &hex!("010000000000000000000000"),
        aad: &hex!(""),
        key: &hex!("0100000000000000000000000000000000000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("b5d3c529dfafac43136d2d11be284d7f"),
        polyval_input: &hex!("0100000000000000000000000000000000000000000000006000000000000000"),
        polyval_result: hex!("6d81a24732fd6d03ae5af544720a1c13"),
        tag: hex!("8ca50da9ae6559e48fd10f6e5c9ca17e"),
        result: &hex!("9aab2aeb3faa0a34aea8e2b18ca50da9ae6559e48fd10f6e5c9ca17e"),
    },
    Rfc8452Vector {
        section: "C.2",
        plaintext: &hex!("01000000000000000000000000000000"),
        aad: &hex!(""),
        key: &hex!("0100000000000000000000000000000000000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("b5d3c529dfafac43136d2d11be284d7f"),
        polyval_input: &hex!("0100000000000000000000000000000000000000000000008000000000000000"),
        polyval_result: hex!("74eee2bf7c9a165f8b25dea73db32a6d"),
        tag: hex!("c9eac6fa700942702e90862383c6c366"),
        result: &hex!("85a01b63025ba19b7fd3ddfc033b3e76c9eac6fa700942702e90862383c6c366"),
    },
    Rfc8452Vector {
        section: "C.2",
        plaintext: &hex!("0100000000000000000000000000000002000000000000000000000000000000"),
        aad: &hex!(""),
        key: &hex!("0100000000000000000000000000000000000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("b5d3c529dfafac43136d2d11be284d7f"),
        polyval_input: &hex!(
            "010000000000000000000000000000000200000000000000000000000000000000000000000000000001000000000000"
        ),
        polyval_result: hex!("899b6381b3d46f0def7aa0517ba188f5"),
        tag: hex!("e819e63abcd020b006a976397632eb5d"),
        result: &hex!(
            "4a6a9db4c8c6549201b9edb53006cba821ec9cf850948a7c86c68ac7539d027fe819e63abcd020b006a976397632eb5d"
        ),
    },
    Rfc8452Vector {
        section: "C.2",
        plaintext: &hex!(
            "010000000000000000000000000000000200000000000000000000000000000003000000000000000000000000000000"
        ),
        aad: &hex!(""),
        key: &hex!("0100000000000000000000000000000000000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("b5d3c529dfafac43136d2d11be284d7f"),
        polyval_input: &hex!(
            "01000000000000000000000000000000020000000000000000000000000000000300000000000000000000000000000000000000000000008001000000000000"
        ),
        polyval_result: hex!("c1f8593d8fc29b0c290cae1992f71f51"),
        tag: hex!("790bc96880a99ba804bd12c0e6a22cc4"),
        result: &hex!(
            "c00d121893a9fa603f48ccc1ca3c57ce7499245ea0046db16c53c7c66fe717e39cf6c748837b61f6ee3adcee17534ed5790bc96880a99ba804bd12c0e6a22cc4"
        ),
    },
    Rfc8452Vector {
        section: "C.2",
        plaintext: &hex!(
            "01000000000000000000000000000000020000000000000000000000000000000300000000000000000000000000000004000000000000000000000000000000"
        ),
        aad: &hex!(""),
        key: &hex!("0100000000000000000000000000000000000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("b5d3c529dfafac43136d2d11be284d7f"),
        polyval_input: &hex!(
            "0100000000000000000000000000000002000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000000000000000000000002000000000000"
        ),
        polyval_result: hex!("6ef38b06046c7c0e225efaef8e2ec4c4"),
        tag: hex!("112864c269fc0d9d88c61fa47e39aa08"),
        result: &hex!(
            "c2d5160a1f8683834910acdafc41fbb1632d4a353e8b905ec9a5499ac34f96c7e1049eb080883891a4db8caaa1f99dd004d80487540735234e3744512c6f90ce112864c269fc0d9d88c61fa47e39aa08"
        ),
    },
    Rfc8452Vector {
        section: "C.2",
        plaintext: &hex!("0200000000000000"),
        aad: &hex!("01"),
        key: &hex!("0100000000000000000000000000000000000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("b5d3c529dfafac43136d2d11be284d7f"),
        polyval_input: &hex!(
            "010000000000000000000000000000000200000000000000000000000000000008000000000000004000000000000000"
        ),
        polyval_result: hex!("34e57bafe011b9b36fc6821b7ffb3354"),
        tag: hex!("91213f267e3b452f02d01ae33e4ec854"),
        result: &hex!("1de22967237a813291213f267e3b452f02d01ae33e4ec854"),
    },
    Rfc8452Vector {
        section: "C.2",
        plaintext: &hex!("020000000000000000000000"),
        aad: &hex!("01"),
        key: &hex!("0100000000000000000000000000000000000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("b5d3c529dfafac43136d2d11be284d7f"),
        polyval_input: &hex!(
            "010000000000000000000000000000000200000000000000000000000000000008000000000000006000000000000000"
        ),
        polyval_result: hex!("5c47d68a22061c1ad5623a3b66a8e206"),
        tag: hex!("c1a4a19ae800941ccdc57cc8413c277f"),
        result: &hex!("163d6f9cc1b346cd453a2e4cc1a4a19ae800941ccdc57cc8413c277f"),
    },
    Rfc8452Vector {
        section: "C.2",
        plaintext: &hex!("02000000000000000000000000000000"),
        aad: &hex!("01"),
        key: &hex!("0100000000000000000000000000000000000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("b5d3c529dfafac43136d2d11be284d7f"),
        polyval_input: &hex!(
            "010000000000000000000000000000000200000000000000000000000000000008000000000000008000000000000000"
        ),
        polyval_result: hex!("452896726c616746f01d11d82911d478"),
        tag: hex!("b292d28ff61189e8e49f3875ef91aff7"),
        result: &hex!("c91545823cc24f17dbb0e9e807d5ec17b292d28ff61189e8e49f3875ef91aff7"),
    },
    Rfc8452Vector {
        section: "C.2",
        plaintext: &hex!("0200000000000000000000000000000003000000000000000000000000000000"),
        aad: &hex!("01"),
        key: &hex!("0100000000000000000000000000000000000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("b5d3c529dfafac43136d2d11be284d7f"),
        polyval_input: &hex!(
            "01000000000000000000000000000000020000000000000000000000000000000300000000000000000000000000000008000000000000000001000000000000"
        ),
        polyval_result: hex!("4e58c1e341c9bb0ae34eda9509dfc90c"),
        tag: hex!("aea1bad12702e1965604374aab96dbbc"),
        result: &hex!(
            "07dad364bfc2b9da89116d7bef6daaaf6f255510aa654f920ac81b94e8bad365aea1bad12702e1965604374aab96dbbc"
        ),
    },
    Rfc8452Vector {
        section: "C.2",
        plaintext: &hex!(
            "020000000000000000000000000000000300000000000000000000000000000004000000000000000000000000000000"
        ),
        aad: &hex!("01"),
        key: &hex!("0100000000000000000000000000000000000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("b5d3c529dfafac43136d2d11be284d7f"),
        polyval_input: &hex!(
            "0100000000000000000000000000000002000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000008000000000000008001000000000000"
        ),
        polyval_result: hex!("2566a4aff9a525df9772c16d4eaf8d2a"),
        tag: hex!("03332742b228c647173616cfd44c54eb"),
        result: &hex!(
            "c67a1f0f567a5198aa1fcc8e3f21314336f7f51ca8b1af61feac35a86416fa47fbca3b5f749cdf564527f2314f42fe2503332742b228c647173616cfd44c54eb"
        ),
    },
    Rfc8452Vector {
        section: "C.2",
        plaintext: &hex!(
            "02000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000005000000000000000000000000000000"
        ),
        aad: &hex!("01"),
        key: &hex!("0100000000000000000000000000000000000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("b5d3c529dfafac43136d2d11be284d7f"),
        polyval_input: &hex!(
            "010000000000000000000000000000000200000000000000000000000000000003000000000000000000000000000000040000000000000000000000000000000500000000000000000000000000000008000000000000000002000000000000"
        ),
        polyval_result: hex!("da58d2f61b0a9d343b2f37fb0c519733"),
        tag: hex!("5bde0285037c5de81e5b570a049b62a0"),
        result: &hex!(
            "67fd45e126bfb9a79930c43aad2d36967d3f0e4d217c1e551f59727870beefc98cb933a8fce9de887b1e40799988db1fc3f91880ed405b2dd298318858467c895bde0285037c5de81e5b570a049b62a0"
        ),
    },
    Rfc8452Vector {
        section: "C.2",
        plaintext: &hex!("02000000"),
        aad: &hex!("010000000000000000000000"),
        key: &hex!("0100000000000000000000000000000000000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("b5d3c529dfafac43136d2d11be284d7f"),
        polyval_input: &hex!(
            "010000000000000000000000000000000200000000000000000000000000000060000000000000002000000000000000"
        ),
        polyval_result: hex!("6dc76ae84b88916e073a303aafde05cf"),
        tag: hex!("1835e517741dfddccfa07fa4661b74cf"),
        result: &hex!("22b3f4cd1835e517741dfddccfa07fa4661b74cf"),
    },
    Rfc8452Vector {
        section: "C.2",
        plaintext: &hex!("0300000000000000000000000000000004000000"),
        aad: &hex!("010000000000000000000000000000000200"),
        key: &hex!("0100000000000000000000000000000000000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("b5d3c529dfafac43136d2d11be284d7f"),
        polyval_input: &hex!(
            "010000000000000000000000000000000200000000000000000000000000000003000000000000000000000000000000040000000000000000000000000000009000000000000000a000000000000000"
        ),
        polyval_result: hex!("973ef4fd04bd31d193816ab26f8655ca"),
        tag: hex!("b879ad976d8242acc188ab59cabfe307"),
        result: &hex!("43dd0163cdb48f9fe3212bf61b201976067f342bb879ad976d8242acc188ab59cabfe307"),
    },
    Rfc8452Vector {
        section: "C.2",
        plaintext: &hex!("030000000000000000000000000000000400"),
        aad: &hex!("0100000000000000000000000000000002000000"),
        key: &hex!("0100000000000000000000000000000000000000000000000000000000000000"),
        nonce: hex!("030000000000000000000000"),
        auth_key: hex!("b5d3c529dfafac43136d2d11be284d7f"),
        polyval_input: &hex!(
            "01000000000000000000000000000000020000000000000000000000000000000300000000000000000000000000000004000000000000000000000000000000a0000000000000009000000000000000"
        ),
        polyval_result: hex!("2cbb6b7ab2dbffefb797f825f826870c"),
        tag: hex!("cfcdf5042112aa29685c912fc2056543"),
        result: &hex!("462401724b5ce6588d5a54aae5375513a075cfcdf5042112aa29685c912fc2056543"),
    },
    Rfc8452Vector {
        section: "C.2",
        plaintext: &hex!(""),
        aad: &hex!(""),
        key: &hex!("e66021d5eb8e4f4066d4adb9c33560e4f46e44bb3da0015c94f7088736864200"),
        nonce: hex!("e0eaf5284d884a0e77d31646"),
        auth_key: hex!("e40d26f82774aa27f47b047b608b9585"),
        polyval_input: &hex!("00000000000000000000000000000000"),
        polyval_result: hex!("00000000000000000000000000000000"),
        tag: hex!("169fbb2fbf389a995f6390af22228a62"),
        result: &hex!("169fbb2fbf389a995f6390af22228a62"),
    },
    Rfc8452Vector {
        section: "C.2",
        plaintext: &hex!("671fdd"),
        aad: &hex!("4fbdc66f14"),
        key: &hex!("bae8e37fc83441b16034566b7a806c46bb91c3c5aedb64a6c590bc84d1a5e269"),
        nonce: hex!("e4b47801afc0577e34699b9e"),
        auth_key: hex!("b546f5a850d0a90adfe39e95c2510fc6"),
        polyval_input: &hex!(
            "4fbdc66f140000000000000000000000671fdd0000000000000000000000000028000000000000001800000000000000"
        ),
        polyval_result: hex!("b91f91f96b159a7c611c05035b839e92"),
        tag: hex!("93da9bb81333aee0c785b240d319719d"),
        result: &hex!("0eaccb93da9bb81333aee0c785b240d319719d"),
    },
    Rfc8452Vector {
        section: "C.2",
        plaintext: &hex!("195495860f04"),
        aad: &hex!("6787f3ea22c127aaf195"),
        key: &hex!("6545fc880c94a95198874296d5cc1fd161320b6920ce07787f86743b275d1ab3"),
        nonce: hex!("2f6d1f0434d8848c1177441f"),
        auth_key: hex!("e156e1f9b0b07b780cbe30f259e3c8da"),
        polyval_input: &hex!(
            "6787f3ea22c127aaf195000000000000195495860f040000000000000000000050000000000000003000000000000000"
        ),
        polyval_result: hex!("2c480ed9d236b1df24c6eec109bd40c1"),
        tag: hex!("6b62b84dc40c84636a5ec12020ec8c2c"),
        result: &hex!("a254dad4f3f96b62b84dc40c84636a5ec12020ec8c2c"),
    },
    Rfc8452Vector {
        section: "C.2",
        plaintext: &hex!("c9882e5386fd9f92ec"),
        aad: &hex!("489c8fde2be2cf97e74e932d4ed87d"),
        key: &hex!("d1894728b3fed1473c528b8426a582995929a1499e9ad8780c8d63d0ab4149c0"),
        nonce: hex!("9f572c614b4745914474e7c7"),
        auth_key: hex!("0533fd71f4119257361a3ff1469dd4e5"),
        polyval_input: &hex!(
            "489c8fde2be2cf97e74e932d4ed87d00c9882e5386fd9f92ec0000000000000078000000000000004800000000000000"
        ),
        polyval_result: hex!("bf160bc9ded8c63057d2c38aae552fb4"),
        tag: hex!("c0fd3dc6628dfe55ebb0b9fb2295c8c2"),
        result: &hex!("0df9e308678244c44bc0fd3dc6628dfe55ebb0b9fb2295c8c2"),
    },
    Rfc8452Vector {
        section: "C.2",
        plaintext: &hex!("1db2316fd568378da107b52b"),
        aad: &hex!("0da55210cc1c1b0abde3b2f204d1e9f8b06bc47f"),
        key: &hex!("a44102952ef94b02b805249bac80e6f61455bfac8308a2d40d8c845117808235"),
        nonce: hex!("5c9e940fea2f582950a70d5a"),
        auth_key: hex!("64779ab10ee8a280272f14cc8851b727"),
        polyval_input: &hex!(
            "0da55210cc1c1b0abde3b2f204d1e9f8b06bc47f0000000000000000000000001db2316fd568378da107b52b00000000a0000000000000006000000000000000"
        ),
        polyval_result: hex!("cc86ee22c861e1fd474c84676b42739c"),
        tag: hex!("404099c2587f64979f21826706d497d5"),
        result: &hex!("8dbeb9f7255bf5769dd56692404099c2587f64979f21826706d497d5"),
    },
    Rfc8452Vector {
        section: "C.2",
        plaintext: &hex!("21702de0de18baa9c9596291b08466"),
        aad: &hex!("f37de21c7ff901cfe8a69615a93fdf7a98cad481796245709f"),
        key: &hex!("9745b3d1ae06556fb6aa7890bebc18fe6b3db4da3d57aa94842b9803a96e07fb"),
        nonce: hex!("6de71860f762ebfbd08284e4"),
        auth_key: hex!("27c2959ed4daea3b1f52e849478de376"),
        polyval_input: &hex!(
            "f37de21c7ff901cfe8a69615a93fdf7a98cad481796245709f0000000000000021702de0de18baa9c9596291b0846600c8000000000000007800000000000000"
        ),
        polyval_result: hex!("c4fa5e5b713853703bcf8e6424505fa5"),
        tag: hex!("b3080d28f6ebb5d3648ce97bd5ba67fd"),
        result: &hex!("793576dfa5c0f88729a7ed3c2f1bffb3080d28f6ebb5d3648ce97bd5ba67fd"),
    },
    Rfc8452Vector {
        section: "C.2",
        plaintext: &hex!("b202b370ef9768ec6561c4fe6b7e7296fa85"),
        aad: &hex!("9c2159058b1f0fe91433a5bdc20e214eab7fecef4454a10ef0657df21ac7"),
        key: &hex!("b18853f68d833640e42a3c02c25b64869e146d7b233987bddfc240871d7576f7"),
        nonce: hex!("028ec6eb5ea7e298342a94d4"),
        auth_key: hex!("670b98154076ddb59b7a9137d0dcc0f0"),
        polyval_input: &hex!(
            "9c2159058b1f0fe91433a5bdc20e214eab7fecef4454a10ef0657df21ac70000b202b370ef9768ec6561c4fe6b7e7296fa850000000000000000000000000000f0000000000000009000000000000000"
        ),
        polyval_result: hex!("4e4108f09f41d797dc9256f8da8d58c7"),
        tag: hex!("454fc2a154fea91f8363a39fec7d0a49"),
        result: &hex!("857e16a64915a787637687db4a9519635cdd454fc2a154fea91f8363a39fec7d0a49"),
    },
    Rfc8452Vector {
        section: "C.2",
        plaintext: &hex!("ced532ce4159b035277d4dfbb7db62968b13cd4eec"),
        aad: &hex!("734320ccc9d9bbbb19cb81b2af4ecbc3e72834321f7aa0f70b7282b4f33df23f167541"),
        key: &hex!("3c535de192eaed3822a2fbbe2ca9dfc88255e14a661b8aa82cc54236093bbc23"),
        nonce: hex!("688089e55540db1872504e1c"),
        auth_key: hex!("cb8c3aa3f8dbaeb4b28a3e86ff6625f8"),
        polyval_input: &hex!(
            "734320ccc9d9bbbb19cb81b2af4ecbc3e72834321f7aa0f70b7282b4f33df23f16754100000000000000000000000000ced532ce4159b035277d4dfbb7db62968b13cd4eec00000000000000000000001801000000000000a800000000000000"
        ),
        polyval_result: hex!("ffd503c7dd712eb3791b7114b17bb0cf"),
        tag: hex!("9d6c7029675b89eaf4ba1ded1a286594"),
        result: &hex!("626660c26ea6612fb17ad91e8e767639edd6c9faee9d6c7029675b89eaf4ba1ded1a286594"),
    },
    Rfc8452Vector {
        section: "C.3",
        plaintext: &hex!("000000000000000000000000000000004db923dc793ee6497c76dcc03a98e108"),
        aad: &hex!(""),
        key: &hex!("0000000000000000000000000000000000000000000000000000000000000000"),
        nonce: hex!("000000000000000000000000"),
        auth_key: hex!("dc95c078a24089895275f3d86b4fb868"),
        polyval_input: &hex!(
            "000000000000000000000000000000004db923dc793ee6497c76dcc03a98e10800000000000000000001000000000000"
        ),
        polyval_result: hex!("7367cdb411b730128dd56e8edc0eff56"),
        tag: hex!("ffffffff000000000000000000000000"),
        result: &hex!(
            "f3f80f2cf0cb2dd9c5984fcda908456cc537703b5ba70324a6793a7bf218d3eaffffffff000000000000000000000000"
        ),
    },
    Rfc8452Vector {
        section: "C.3",
        plaintext: &hex!("eb3640277c7ffd1303c7a542d02d3e4c0000000000000000"),
        aad: &hex!(""),
        key: &hex!("0000000000000000000000000000000000000000000000000000000000000000"),
        nonce: hex!("000000000000000000000000"),
        auth_key: hex!("dc95c078a24089895275f3d86b4fb868"),
        polyval_input: &hex!(
            "eb3640277c7ffd1303c7a542d02d3e4c000000000000000000000000000000000000000000000000c000000000000000"
        ),
        polyval_result: hex!("7367cdb411b730128dd56e8edc0eff56"),
        tag: hex!("ffffffff000000000000000000000000"),
        result: &hex!(
            "18ce4f0b8cb4d0cac65fea8f79257b20888e53e72299e56dffffffff000000000000000000000000"
        ),
    },
];
