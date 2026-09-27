#include <gtest/gtest.h>
#include "TestHelpers/AssertThrowEx.hpp"

#include <iterator>
#include <stdexcept>
#include <vector>
#include <array>
#include <cstdio>
#include <cstdint>
#include <cstring>

#include "Cipher/Stream/Arc4/Arc4Crypt.hpp"
#include "Service/ChaosException.hpp"

using namespace Chaos::Cipher::Stream::Arc4;

static std::vector<uint8_t> StrToU8Vec(const char * str)
{
    std::vector<uint8_t> result;
    result.reserve(strlen(str));

    for (; *str != '\0'; ++str)
    {
        result.push_back(static_cast<uint8_t>(*str));
    }

    return result;
}

static std::vector<uint8_t> HexStrToU8Vec(const char * str)
{
    size_t strLen = strlen(str);

    if (strLen % 2 != 0)
    {
        throw std::invalid_argument("HexStrToU8Vec(): expected a string of even length");
    }

    std::vector<uint8_t> result;
    result.reserve(strLen / 2);

    for (size_t i = 0; i + 1 < strLen; i += 2)
    {
        static_assert(sizeof(unsigned char) == sizeof(uint8_t));

        uint8_t byte;
        if (sscanf(str + i, "%2hhx", &byte) != 1)
        {
            throw std::runtime_error("HexStrToU8Vec(): sscanf failed");
        }

        result.push_back(byte);
    }

    return result;
}

TEST(Arc4CryptTests, BasicTest)
{
    const std::vector<uint8_t> key = StrToU8Vec("Secret");
    const std::vector<uint8_t> data = StrToU8Vec("Attack at dawn");

    std::vector<uint8_t> ciphertext;
    ciphertext.resize(data.size());

    {
        Arc4Crypt arc4;
        arc4.Rekey(key.begin(), key.end());

        arc4.Encrypt(ciphertext.begin(), data.begin(), data.size());
    }

    ASSERT_EQ(std::vector<uint8_t>({ 0x45, 0xA0, 0x1F, 0x64, 0x5F, 0xC3, 0x5B,
                                     0x38, 0x35, 0x52, 0x54, 0x4B, 0x9B, 0xF5 }),
              ciphertext);

    std::vector<uint8_t> recoveredData;
    recoveredData.resize(data.size());

    {
        Arc4Crypt arc4;
        arc4.Rekey(key.begin(), key.end());

        arc4.Decrypt(recoveredData.begin(), ciphertext.begin(), ciphertext.size());
    }

    ASSERT_EQ(data, recoveredData);
}

TEST(Arc4CryptTests, LongInputTest)
{
    Arc4Crypt arc4;

    {
        uint8_t key[] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
        arc4.Rekey(key, key + std::size(key));

        const std::vector<uint8_t> plaintext = HexStrToU8Vec(
            "a8393752ed62222a0dab7190cc39ab8f2c11fa3adaa2816f126351aa64d91d495d"
            "886a2ac47cf4218581cf7c6a5a5da2bbaab8388a5dbb446986b77b14b9ec3616cb"
            "54c4f78aaaa1e7e1b75adab165fbbab80ca6fac35b96c7bfbf08630d15556bce01"
            "afa6ac65c2d0bf703aeeaecf5cb71f2ea81ea8e3c1478f4db1b6cced6b4b1c95f3"
            "de5ed1528d1ed73a8c5ad87d145b5cc95752e916ba1681546049a688bb112107b9"
            "551e9e5f8f14b78a76e32f6ef980acb8a8cf6f9e6dbff58ae2a83732f61b6845eb"
            "da2716970f549e1fd3374377e07e626ae9869fb6df6dd06643b2bf0d485e65499a"
            "95c2092d0905724339a16fd1da02f15063584977041630c1ba5a76cd329fa11686"
            "882df05b3294026ac1f487e89a5017b6dd79f721d3450621db05239fdaa2aa3498"
            "f77fbbcdea91607b69c307c521c81d0652dedfa6a1be742db3773d18d07a325df3"
            "1326da1b2dffe53d5b2ea25a9ee59dcac9f4d3ca04ce41a73e7ccf8b77e11f6ba6"
            "4fd59f672755ed21e4ed98a3d894d2519feee6edb16372de3e9bfb535e9881378d"
            "fdcdd7bed810bc129410328d1e961175ff8c21902bad1ace07cb3e70887658408f"
            "48a9d19e82ffd27fb7610e67ce09637ff4fbd7a33eace9c244741c12edc2b8d7e7"
            "da246b37aa528cbcb2fbcd2c00e213b608804124e623ca70326936e4a9f43fb7a3"
            "0dffac8956f6a17e6d9d58dbd589e1490e884e28a82792390319bf9eb00456767b"
            "51c5bb0a60e3063b814d815c28c065dbb33bfd24575f9f68589f91218a1bc54611"
            "df0fcb1bcca7588ebf426fe0bc498e8277218685a3ec5a02d0797bae76d920f17c"
            "c07618a9753341fe725eb37ebbf90b4d207299eb3c5f6d6a4d524ce13a0a3c0ebe"
            "85c75e493966a7542e568a3a9a512319da11dd9f4f419511ea4d444b23ac3cc0df"
            "13392a2840a5fe1ac8a93ad2ac11cd2c2a20");

        const std::vector<uint8_t> expected = HexStrToU8Vec(
            "481372bd1a1e7c55f158aa921838660eb6d5801235bb5cc78791e112f1655c9cc2"
            "4403edff9cf6a4e1947d29c83401ddd4ac9d65110195f5665c645f02ee40045bad"
            "c5bef522382ec34bea8d421db9b834ad1e65a093a687c4b788105a9d1a9be50a34"
            "60d2ddbe03f64b1dc33debac1c688ea8a09c2e2eb2e469d762c2b031bdbdc6c623"
            "159a42e08ab8f0bbf4be9225176c0ddf3367dcede7e4cea92469ca1fd31f81b0db"
            "29e4a1c8444376001a705cd93b1f94e939d70489f58d1cd6cd55f867e8c19b1fd4"
            "98864328d5a424cdd339ea51f47878de55ba5a9f9c19720a63511cfd5b32f05a6a"
            "24e41c109c316b52327238f0e57020b8e17e637588d8cd7c03537eacf4c42809e5"
            "33d782e02a1f9caf744414c8ce9da657be2d72d41ab60b116a5edbd67c1a70ebcf"
            "0ce6c70d92fcbcf800fba5668e5c4dcb1aefb135ecf1673db7e4007005e20f32d6"
            "b24f260c20606708fe61472694448204dfdeb1f382f0a974f16425e9f378a78452"
            "a508f045c453cd80f202984dffb0c6fc017fa025d292abb6f220a830b53729c86c"
            "021a67387b311f7e980215c7ee64ab926c420052347fe4f9ebd044e2214be17e5b"
            "dd548ba1fbb218c020e2123ac568d217c179550f97a7e1534c012fe7f07d17f4d3"
            "0db0fe2ad95a63577ba8c3605e88d976328bd9fa8906cae772f9b996a355a8104a"
            "22ec58db00a09afb89cf6df526d9dc935ce4c710c226da66269d0a60b65a0995cb"
            "d84a560d14001a53bd15e1300a5a927fd65f06bfc12842950722cd6addbac3aa7c"
            "714449392c4888195ae1939504b133e7a7628884b5cb75edb6ecc83401e5b930a5"
            "0c599720cd52a7fb5d7ef1b96455f2687b98b204e3f3afc666d8d00cba1e11e467"
            "f3391feb4ff2cdb4c5d9d865eacee9235767f983241f5c3acce862bce2c98a204f"
            "5902be8887b7b465ea2e16d86ac2a21dbc5d");

        std::vector<uint8_t> fact(678);
        arc4.Encrypt(fact.begin(), plaintext.begin(), 678);

        ASSERT_EQ(expected, fact);
    }

    {
        uint8_t key[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
        arc4.Rekey(key, key + std::size(key));

        const std::vector<uint8_t> plaintext = HexStrToU8Vec(
            "76eb38de76b92dbbf764b06b167ce749c6fd1a3845e5173c08001914cf676cf767"
            "367bd7620125a8d6fe82f82dd3df4f70bef20691c128261673666421e2b1c0c2e8"
            "957b0be0aef916f43a3ad3b187bc0518f4d2e105cba73958d0551c219a4d8a5916"
            "61592abc2becf4c7e83964114ee815bad904cc8c9a7bae2e1c75930ff440101ecd"
            "98f220d998aec10cbaa4dfb747f4e789cafd98eeeb755c9fc48f4c5e951fa3695a"
            "7f10f0f55a70c314c490722a5fadd5a511d83d42c0b1f5bbc61d44e1fec8688f6a"
            "7aea301f9246ef8e3448ee76b0a0b8f31140d9fe1da17f70d4b687d9558c49cf29"
            "1d2f032dadc07d8715f87b4c39e26a9273fb493c673d795ad74928631cfd3c8728"
            "05b2a818906fa0a029af9c98599f061d615da59c7f5a77a830058370ac5a4989ca"
            "1e8c0ef9c2d069388daa3f165f5d0d2c9d1298a20f2d85bdc55f84df075c709675"
            "08503b96758552be4b0cd82ecb93d240ad0961fabc222e4fcb42ff8f7e1af76c3a"
            "f0e66fa112d71ac779d440a71c76438ee80c870e5c7aa9ab9350a953882fc23f8d"
            "69f5b37da01991cc9ef23e19931a434e9b80e7f4109696b795c49042c47e706fd8"
            "b0daa986c6e089c95becc67e2a6ec1500ec570b1ee4e5cedbf8d19589a012f8c93"
            "f138559509b444f5555e4beb3d59c4e5d77cf4fc2d64cf7c2323f155721786a542"
            "da9f2f2054fb3577521fff02a510a120435bdfc2ebed3ce0d2630793692915ee87"
            "cfa79a9ab036d98f14466c0cc14e3b19c6c6b6158fa673b071a6757614fee2f41c"
            "3afae603d12326cba0e7ec8b209b01a4c2c6493334a513f5fc60ae9dea84f5b81b"
            "feeee4e8bc4b485545633704bb8e5543e9120e70dad8bddea579e748032a117f99"
            "6bf48a57c903b74b67fc4f73ad41122de616a39dbcea0dd42aa5b81f74ec207790"
            "151c2daa0aebe1bbf34bcc2a227128e4a48c4c28cb355881b5a05bd955ab287aaa"
            "471148f20f10c00923434a023a834d3a164237f240cb59373d806cc1d013e0a147"
            "daa0d39a2e44771a6ef9ddc2731d736774bd377d315aac529103f35736d45e7e55"
            "4534058a663b3afd9d934e43de6245de7ce91ab4515bbb938fc627bb7952eaff8e"
            "2f50910b52c7b2054be54a8cb3798ea29acc859146dfee88836597c3f70e207781"
            "d4146ec9c18166f69e9cbfc89bcbc07498921b3bd1fd8beac4b93bc53150b30767"
            "000f0d6d8671f52c4f370c97db504ea3a8f0b371ccc48870c2a241eed53b73eacb"
            "6125725fbb0bacfd7de0c7747fd663736c714796c625d30c071618669bd301e718"
            "6c01fb0735175d114f50499ddcb7775c7f3e1f30a309e9e84fab1feccbc420b686"
            "e9c98d1365154b8b07854b2f6d15ab9d423377149d584ee4eabf2ba21c19382899"
            "cc4dbb465987601edea1c2d52126f93044844b5fe687a57d4c858662f0ced422d0");

        const std::vector<uint8_t> expected = HexStrToU8Vec(
            "c4d25bdb8684ed9c3ba7e2211c6dffe1af7f8e775d1995e981c41ab0b56a65eed1"
            "b90315ef14fd8af5b2ee40e8251be3c00764a2823ff2723ec31ee2934234d29448"
            "105e0c60f62965c170bea54e60ce64fc07a3ee06c0ab2dd1b91ea5a8b25aefcbb3"
            "837614393ad928d98288403ac2cf60bee9e7d09fc7b397b6c2580000ca8f4179c3"
            "9cf97d41f8f23bc9e1caa492bdb1fe6879a727d0bf54dba470fce729e620920d85"
            "0a99a3a208de2926de5ba9c5b5ff7fa100370048d93db6b55e059aa1fcbbc0f164"
            "ce7d5acfbf18e9fc178c4a719f8c199dd9f9e655b4cf074f599ef0653194f735bb"
            "d7e3fa4182b7c84ad6d0b05d0b2b0670f5b954f6ca85cfc47955d49537fed15c4c"
            "18c577d7efe22c3376e62e80b51cc877b7eb0293499f174e13c1018cee9843911c"
            "9812c24e57c8eb38f9669248cac748291946a216ac7b504cc51959a2ec390383ea"
            "09553fd61d5efdf203a8fffab422987f3e08d3a05135071ec3ce5599e39ece89f2"
            "c3988c1c49e55c429a73de1040b64170d4ee40977dd604e7a53b60a5eff8cbe26a"
            "febbd1caa9d24d3329cf37e1548966e2c3e491013fe8ea0e6aeba3f1a3344a37fe"
            "f3a6f9e7ebd2fc7c2e4c57c4d920a0ff4d2a1923df96a24953986ffab0bb1d0260"
            "c30d86683e718fed3c290bf0fc4456c6a2dff731cf23abcb835ddec61154b4cf99"
            "79dd98f099222ddff1222a1524d8be60023f8646afdf9b3a405ffcadddb1138f71"
            "8b4573819d67249865e552ed20aa1af722f1502093206c5384d824f8278970e50f"
            "6b0ad1bb827f6da3e92273c5b0948ae2b7cc711b2f7ed4593fbee22848070281a6"
            "3663b97916367dca634da34ec0fe71a282db4421947b473c889d95dd9ad6a5be21"
            "4e55590e512876f51e74dc7a816a9db5c8eeaf73347c25955ec7cd16f801b5d789"
            "a29d2572110c3fe595992ddc5b2be74777faef93280342db8575cb14669acc139f"
            "dbb2a5c192e7aa357c8447c2640d64f00c941d0a5ea9ba4d93fc63e4217b50bca3"
            "07fba10ba433253d153b89c1ec28b908153aa1c01390df180ece1f4704af8055bb"
            "b82cfcad10bb7f83bf782c20532d4e7f8276d094b100436ca40150a5febf4b7d17"
            "f3757daf9ed4095f7c5007360160bfad33eae776d2014c99c5a04f22bc5358e681"
            "502caf43e86facfabfc0a98d5899f2b69f843859adc45a1982be998105e77bb5de"
            "612c1f61d56947af63a7b2cf64a976de786a2e65b3e3ddb3c72e82c1404912fb92"
            "c24bf84dc22d74d90aa9005412d24a8420186576141e5c96dd7dcd830509910ec0"
            "d68a64d08eea3b51ba6682e725c16b2a41f34dd887bff202037d6beda7ad45fc28"
            "fcfea53f07dd6ad677a8e42e7b70d4bb4ebe0c0eeae62fff0e530090a8af4b84f2"
            "7f8bf75a8c11ad613cd7cd0b04909c9053e00e4d76cf43dda18ed0d660fd5b255d");

        std::vector<uint8_t> fact(1023);
        arc4.Encrypt(fact.begin(), plaintext.begin(), 1023);

        ASSERT_EQ(expected, fact);
    }

    {
        uint8_t key[] = { 0x05, 0x04, 0x03, 0x02, 0x01 };
        arc4.Rekey(key, key + std::size(key));

        const std::vector<uint8_t> plaintext = HexStrToU8Vec(
            "ee44ce378d605ff867bb220e544de6f6aa5194c7c5c089e044e7a1a25841c10c81"
            "e55fd79d0ad2b43761a3186860d53db4a55e18798f27ef025007f9cc4e4db7e655"
            "0ce083941dcfaed6f91bd905839cf8166b5b5d826e1c6fe67f3be9dc2aa495fe2e"
            "659b393d6bae0ca08023dfc4f650b3a87d9179a0ae1166377c77e9035148e6d693"
            "ac72bef1ad4659eed8efaa77fb023b346f8809c854898b0d385f52e1a1359306a5"
            "5159b574ff85d1e9f981abe0ad17630160da257e526df5f63becd3e7ade045206b"
            "475c5de5de10a0848c011fd761299fa91846b4303944a8bda13b54fb19859b831f"
            "0eb7dc0051ef892c53851f388f459aabbe290d8f73593d8fd35f58f737eccca465"
            "23f8756762741e4bfd4b72215e4ff9597773f9fd808302b1c47be543f36f424ff8"
            "b7e0fbc6d80fedcd48860fcc56ee9535954932d9c8b7a649186658a129f536e888"
            "09adef404b40171606327da2f405c8aca4a2f490d467e0cdef26e26c0efa4180b7"
            "906ce036cc0028f699072ab8967de3cb46bfe3297b70c0d1ad12d61b5c210ac8aa"
            "08495484e97631f8c327bba07cadbb08a726ab6bdf1a3377086ac1456ac6599456"
            "ff40354a550466b0048bf02260adeabb363240d0fda968234a1fb4b8a2f6006f46"
            "d1e17b32c05fceea1f4441c09112121bde260b8eeb12225041677fdec3c931b397"
            "848e91d76d79d902796f40969764f101cb2914500acdd685154c21c01275ba9cc7"
            "16d398ad2d2d796633231cb3cc2de19f19726a9ee25bca3ef9ff65f757005a8435"
            "ae33a804c361d62ddee3b88a0eadc9ef95476bc109ea4ec2967933e8914331cef2"
            "c3316d895f935b1deca4e4683d95c70c22df4642d2f5383e25401dcd172de407fd"
            "776e5ffc4cc191610dd1c15dd6c55b4ce0f6d0dc1336881edbacc82df3279f98b8"
            "dd657ec3ae7ffd82a4903caf7a80013b08563fa3c66b226ba00e0f311e597a2e39"
            "66fd678e33a503c7f411366c9b739c34f1f88bd58fd8b84613066425ee4c9d6764"
            "480c8a4bfee09af7389bf3d2ca8c450bb19910b4d65bc397e4cc919c2605681fe1"
            "17b77e9960c79802e5f4953135547f63a4f54d22ef0e402bcb57e007d3e68cfb2f"
            "a77b0400c0a59d066e57efe1d4affb58f64dc2208a20898f25d9a58d6e3a147d3e"
            "d14e003a2ec6a8d9f49b57d79379b62b4f372a81a255e0bd9a252410c1ca39c715"
            "637ad911fbd13ba5e0dc5cfeb475579acfbdbced94b0af4b88b5e161f91e5b1496"
            "cc85a7601771f7a4889ec5cdd82f0e30edea12d2689c948041b0f106972fc9dc11"
            "a12dec72d8bf09657259da1e11651b026fedf4340d630305511df86f037007aee2"
            "1b17634b41085fe91b36346ce75ab404dc6717645a641fb6fcd40ae081252fb013"
            "468a8ee8d0a411e471903fd8e7a550becc889589867f59cc0047a1cccbe3d5918b"
            "b4");

        const std::vector<uint8_t> expected = HexStrToU8Vec(
            "a26685123e9b6dbdf6dc047129123c93cafdb6f04418842221d0e79997f8c6a9ac"
            "28c67bfea3e109bbd0a70681401b0bf91190fba6b4dd5a4d6e9893eab4088139ae"
            "d6fb3b8208f6d926d90f5b8a6fb765ed8d8f15ad376b90025c1eb2a532e4103b7e"
            "d9e0208ffb229aa3a2eb77fb69f27c9864c7b0c713d1ee7ae17fcea834bf11bcca"
            "ee752d2a87937f8b5a4df1e4d5bb66344ed6f364b24829f23a51c09c20defbdf45"
            "2c8331d97401563ffc6f2d58003e4d7075e430a07c31d7c520781c6bec6b0a652c"
            "d2659efabbb1b4c83217947fd08cfae5413a6242215097b61fd830802243920da4"
            "17157377125821c088035b580e3d8aff1c59416e5f45437046efa061e799da3cfc"
            "02e0264ad81f4cc17ce989e4bf2a89af4c6eedce62ba271ba51318c51aa6a65183"
            "612d51d5f5a2b530dbc4d8f341425354acbcb0407b491170259f1a24c9287a6abf"
            "5fecc0a844acbe5c6627cf23eb9c7079631bed699f8de1cf7a93b2bd067a0eac62"
            "834b66317d1b5ac4d0637f65816005c3e2c503bb09d8222f994a567a0cf787412c"
            "1b0828e69f51a17bee3d6333cbbd78750cdc88770c8c1bfbda98270117adc10f0a"
            "43ec465d0883ca1c6774475babaa2d5818fbe4f9e46d0d34c0997e9e9f904c7898"
            "4804d43f699a56a12992fc93fdce9ba76be7ce5d637d0affd34ebf5c631c439085"
            "a82abbdfb0e2975410bede8c294e80e26c843987451895e5951820e918680c296c"
            "2470fe9cac37997b0f69697fe934f812d4045d7f09e041289f74caf29879226475"
            "12a6e50433a3a4cdfeda0a9d8b17c2f6983f9239a9e58df4612ad6e9b29fb4ffea"
            "9d4d6a50f3fc31568d48881c37eec9500426e782354fc75b5d6960b137eab260f4"
            "73950269877318667345be13ca79e7e6db0d3887ba3ef3e8a0af686396b6c40b5b"
            "fb9637b26f553bd77ae73f042f89d5bfc6f9689c7b741e9d0663c23154448d649b"
            "3629830f1ca501f6eec27d2b1e63b770fb159301c5dd0a00713aa2af1719a5375f"
            "20be797ba36e75a1701b7d87c7f2874411c671080e193bb4ecb50f796212b326b3"
            "5b004a3bfbf7d1d2c20c5abb72617614cc2701cb51606f6df13d9417dab64e7dcf"
            "6599f9973967ba7500d11f5d02654305ef5a7e080737035f66c9facb810954c419"
            "eb7bf8a8e06a50b46420ba943c6f18ebe4829433587553a192c680f910dfe7e7fa"
            "3d4e1921126805c89ef41c87cefd320690551b1dd81d3081372f449b8932972bc4"
            "fd6eb884d01e3ef433f2cf109fbe8c9081f88449d7b5dff473da0f41202ff8a602"
            "d29c822e0e56e92c5e5d727fe16a0a2570a501dec503da171e12394e001bb9059b"
            "17287e7bfbdaa107d583ef389f0a36b003448b5301e29a82e67f87c94a9dbcc7dc"
            "cce2cdd87940324b59bea30ec0ebd438ba0f8891057c998532f96053d77a8b6e6f"
            "0f");

        std::vector<uint8_t> fact(1024);
        arc4.Encrypt(fact.begin(), plaintext.begin(), 1024);

        ASSERT_EQ(expected, fact);
    }

    {
        uint8_t key[] = { 0xc0, 0x00, 0x00, 0xff, 0xee };
        arc4.Rekey(key, key + std::size(key));

        const std::vector<uint8_t> plaintext = HexStrToU8Vec(
            "5e3e11c92e57c7ca4b137be96a8af123951932930ed005202eab4576fe45c42a81"
            "dad62c94484a77c69c968327dfc8ef770e34c300b0576e61c842c23ae6d46c638d"
            "82143ff17eaaa3dff26da71f24633dc705c16025cb18b232edb338c1698099f805"
            "8eb1b7c8c757c9d76ae2a3bb7a8365fc6303656bd4fd03438e3126046eebba2e41"
            "66322da6e13ec2907713f0e4de0e45ed57432af0bb5143d6908b6c306253bdf860"
            "8e6d834b38b8bc3c1594e9f36b8a2c6306f17069f1a0e55250c736e9009604d45b"
            "8ec458d1599bbec7f3af96750f91d97b78fd3ff3930a4cfa0872b2dd0b4697eb59"
            "b91ac5ad54ee326962cac9a986e2776df2f3fb44f178580aab890f0beacd58b00f"
            "e49914c6c228ceb74d30539291d42bce9bbfc81ade6c93806c1eb686e10933621d"
            "de2526ff4fd6e27779f8c1bf49164a1a02933a2fcee9110c7a28f819d3e42f6502"
            "0840804972f28ad75d8e2d0db610da8f5dce9522e400fea9ca707ba6f989724df2"
            "24ce9945cb54f92116a481ab160e1de1c78dc7016b032a48e4862b97b524840fff"
            "4b4b3c5dc1930688bfcaa1c1cc6a94ee5a9f04d3f69e2b27e476fba60e95ffde24"
            "bf47cf12bea38036526462148a62028fe429cbfe6ff27f87df7dd15d530ad0c048"
            "5d6da334c47a945e3c1e8ab7e208bac74587ca6817a06db6ff2ac3b316aab5d057"
            "405533a832efcf42816bc2f164f307c9692bca0e9069cdf21a0d22c8966683973e"
            "5fab786386356227d3e424541ef8e2e040a142737fb70169374409275c0fb29330"
            "d0b51cbcb30c7dcd017073e4d0bb9d1ae2f67baa5c4011da83da689cb6eae49fa0"
            "8d25cb52fc09178cc8abc41230109d311d8bde87dbf153897e61a44916f48e353b"
            "0c43f8e2e371eb7070d828811bce1e5820c0516f5426d14219dbac0bae253bf993"
            "646d7e0385ecb455ebd4f433584e0536de280e2ca0cb7b3a20f7a6fd918ce33f4e"
            "614906ea32de3c4adf9d4ed15e7503cc49fcf955b72da7f9302106fe12cbc7b31e"
            "e08da4cc218faa9f7d47319e96172669375261550077fc3a7e2179a88701054cf3"
            "e789acb7ddc18767efaee272b1779b28f2aec224de307523bb405ee2818ba3d2ef"
            "a6a55ac34ea0d5ec65e093a27bc17de02a3c78f1cd3b13da759f3cfc4b2cdb00fb"
            "749da0d5ff40fd93977a1678f528197ed76d00d7db73e40176353b7dfc3e1c1194"
            "51bb638bb70cdb4c2787ab1b1ec90489ef261eb36df5e0f551710a1a5c697e07b6"
            "a91152f415795c9df226a2c0bf38e67ab5ebf16a50e5766e8c0e5241476f41048b"
            "bab27183f7b3ca95f48875fc6a959f0d39043e61f55d27531c1a65b6042dd3c100"
            "ec9af71d76afe6e4125815d3e9d7e84646e08e1bff44abfb948d4d5552d59728c4"
            "066914c33c87226a5317301536272995809daab4942ceba4e54c8d3fdf2f1afc15"
            "a4b7");

        const std::vector<uint8_t> expected = HexStrToU8Vec(
            "e0a431fd9470314bb708b95c86eaa97f0581c1b4dd22015460a569c82af7e95990"
            "0e2870de28c6d35c897dad3cd69996e8f016612291a98ff93e5dbbcca13b531254"
            "9f6c6e695267bc4423d78f107f9f0eb966521df49bf089f0b50f113f061bd955c8"
            "6cec39cc5f131877427b74d4a2134f6175e382825acd2e7ef22638913de756845a"
            "1107be360a58f7e38508c13a0a819240e0c1aae0e2ea2aaaca34b7cebd96f6c563"
            "6b29c3a56cd54dbc04b0e298039760a8e1db38aa01f8b51bc9b41bcf8c3324f036"
            "9947fda99c8705c2ca654d6871644b0f5d0b877628e59fc1932458f6d88ddcbe18"
            "89e9e2f7274832a0a3d6f96bea06152d26786e88a414abc5a12466417dde2a4c22"
            "aacf566de0be676785cb90b26a0654a11a35dab9f7fb0e68a3876494c9c58f314d"
            "a75e331238fa760bf84c2537f4888e13a72e2c521f13cb174920f06e56a8b9b2ac"
            "3b7d842b093a958323caed06586385593cdda434703cbb00ec85b8d6dc75e0fc0f"
            "f6804df693658905292e1aaf804ade5cb509dbd6b00d87e653c9a42426f7813ff8"
            "a8002ccf5ac80feb09bbbedcea9f7e1e2b69e47d3d22151b89d01c3f2b2782cbd0"
            "d9d866320076b7f96398ca45ba9561eef0278a3e1a9e62a412b144568ca3d91f5e"
            "829c67120ba86196c462c3092c227e389846d5c2029d358333221614021e2de8ab"
            "c733709529e96373d24ac91f625413221c25cb94cc80377011b920bd5397c6d360"
            "b33a2574778b6f378fd0a6f74877492f9e90f712b411b22d43a9f3e13a0217ea9e"
            "b8af4be516a7a038add3e6ffeea4e1837db05e25f7e54fcf343fd27ec912c21bf4"
            "66dc21df4a8aad54755be47f650eff613e458fad83e10c5a97fc7fe527d3e68518"
            "a967839bacde871e005ede02d2c3a9c8d625a80cd016ebf0767e155f09fc5afdb6"
            "6cafa1f994a72595e652a3899f4cdc7e88381ae7d77fb31255a3755535e77ecbc9"
            "983bcee3ead27f1c4fa03c27d1677e8643c76a417a9d49977e729b7e98d062df69"
            "6c5a2f55ec8bccf03e97face906a51a067991cc30a29822be9e7de25905ec2526c"
            "86a38e4ccba2c7cdab862c84c988beca11e6364ebc311357549c01385be2d3428c"
            "78471a93e603ba41eace7288d1b24299fc89f3a4e405cc7990d4e680644cd3b1dd"
            "56bcc8573fbaf919a440b4057f88e6bd2f04c2f54fe7468670a73a87bee216ec10"
            "c5074e36fd57412449113434259cd12cd51cf28fb9ab6de2890a250b13d6442404"
            "52fa21d81ef314e8d892be6c32a9f303e259b43007faef809d0c199948208cbc6c"
            "1e23bbe5ce9da3f4f36e3688936b7c3d25827a5889290270b81fd6ec8980aef5cf"
            "fa790bafa93f968eac65b5f8bc53034b496edcd960c285badbb70928820b56db28"
            "25a40536d868833e14971dd301bb965354c9de5d740739d501a0bbf649770945be"
            "09f0");

        std::vector<uint8_t> fact(1025);
        arc4.Encrypt(fact.begin(), plaintext.begin(), 1025);

        ASSERT_EQ(expected, fact);
    }
}

TEST(Arc4CryptTests, UninitializedArc4CryptTest)
{
    Arc4Crypt arc4;

    {
        std::array<uint8_t, 10> in = {};
        std::array<uint8_t, 10> out = {};

        ASSERT_THROW_EX(arc4.Encrypt(out.begin(), in.begin(), in.size()),
                        Chaos::Service::ChaosException,
                        {
                            ASSERT_EQ("Arc4Crypt: not initialized", ex.GetMessage());
                        });

        ASSERT_THROW_EX(arc4.Decrypt(out.begin(), in.begin(), in.size()),
                        Chaos::Service::ChaosException,
                        {
                            ASSERT_EQ("Arc4Crypt: not initialized", ex.GetMessage());
                        });
    }
}

TEST(Arc4CryptTests, RekeyTest)
{
    Arc4Crypt arc4;

    const std::vector<uint8_t> data = StrToU8Vec("The quick brown fox jumps over the lazy dog.");

    {
        const std::vector<uint8_t> key = { 0x01, 0x02, 0x03, 0x04, 0x05 };

        std::vector<uint8_t> ciphertext;
        ciphertext.resize(data.size());

        arc4.Rekey(key.begin(), key.end());
        arc4.Encrypt(ciphertext.begin(), data.begin(), data.size());

        ASSERT_EQ(std::vector<uint8_t>({ 0xe6, 0x51, 0x06, 0x25, 0x81, 0x48, 0xa9, 0x44, 0xa7, 0xe3, 0x30,
                                         0x38, 0x65, 0x66, 0x76, 0x88, 0x0f, 0xed, 0xec, 0x6f, 0x72, 0x89,
                                         0xef, 0xa5, 0xfa, 0xe4, 0x6c, 0xd2, 0x1f, 0x7f, 0x29, 0x6d, 0xde,
                                         0xea, 0x58, 0xae, 0xec, 0x6f, 0xa1, 0x02, 0x47, 0x23, 0x0b, 0x96 }),
                  ciphertext);
    }

    {
        const std::vector<uint8_t> key = { 0x05, 0x04, 0x03, 0x02, 0x01 };

        std::vector<uint8_t> ciphertext;
        ciphertext.resize(data.size());

        arc4.Rekey(key.begin(), key.end());
        arc4.Encrypt(ciphertext.begin(), data.begin(), data.size());

        ASSERT_EQ(std::vector<uint8_t>({ 0x18, 0x4a, 0x2e, 0x05, 0xc2, 0x8e, 0x5b, 0x26, 0xfa, 0x47, 0x44,
                                         0x0d, 0x12, 0x28, 0xb4, 0x45, 0x06, 0xc3, 0x5a, 0x17, 0xeb, 0xad,
                                         0x60, 0xb2, 0x16, 0x17, 0x29, 0x4d, 0xaa, 0xcb, 0x27, 0xd1, 0x45,
                                         0xa8, 0xb9, 0xc0, 0x02, 0xd3, 0x4a, 0x9d, 0xe8, 0xde, 0x63, 0x30 }),
                  ciphertext);
    }
}

TEST(Arc4CryptTests, RekeyFailSafetyTest)
{
    const std::vector<uint8_t> key = StrToU8Vec("Secret");
    const std::vector<uint8_t> data = StrToU8Vec("Attack at dawn");

    Arc4Crypt arc4(key.begin(), key.end());

    {
        std::vector<uint8_t> ciphertext;
        ciphertext.resize(data.size());

        arc4.Encrypt(ciphertext.begin(), data.begin(), data.size());

        ASSERT_EQ(std::vector<uint8_t>({ 0x45, 0xA0, 0x1F, 0x64, 0x5F, 0xC3, 0x5B,
                                         0x38, 0x35, 0x52, 0x54, 0x4B, 0x9B, 0xF5 }),
                  ciphertext);
    }

    {
        std::array<uint8_t, 10> in = {};
        std::array<uint8_t, 10> out = {};

        uint8_t smallKey[] = { 0x01, 0x02, 0x03 };
        ASSERT_THROW_EX(arc4.Rekey(smallKey, smallKey + std::size(smallKey)),
                        Chaos::Service::ChaosException,
                        {
                            ASSERT_EQ("Arc4Gen: key is too small", ex.GetMessage());
                        });

        ASSERT_THROW_EX(arc4.Encrypt(out.begin(), in.begin(), in.size()),
                        Chaos::Service::ChaosException,
                        {
                            ASSERT_EQ("Arc4Crypt: not initialized", ex.GetMessage());
                        });

        ASSERT_THROW_EX(arc4.Decrypt(out.begin(), in.begin(), in.size()),
                        Chaos::Service::ChaosException,
                        {
                            ASSERT_EQ("Arc4Crypt: not initialized", ex.GetMessage());
                        });
    }

    {
        std::vector<uint8_t> ciphertext;
        ciphertext.resize(data.size());

        arc4.Rekey(key.begin(), key.end());
        arc4.Encrypt(ciphertext.begin(), data.begin(), data.size());

        ASSERT_EQ(std::vector<uint8_t>({ 0x45, 0xA0, 0x1F, 0x64, 0x5F, 0xC3, 0x5B,
                                         0x38, 0x35, 0x52, 0x54, 0x4B, 0x9B, 0xF5 }),
                  ciphertext);
    }
}

TEST(Arc4CryptTests, EncryptOutIteratorUsageTest)
{
    const std::vector<uint8_t> data = StrToU8Vec("The quick brown fox jumps over the lazy dog.");

    {
        std::array<uint8_t, 5> key = { 0x01, 0x02, 0x03, 0x04, 0x05 };

        Arc4Crypt crypt(key.begin(), key.end());

        std::array<uint8_t, 47> out = {};

        std::array<uint8_t, 47> expected =
        {
            0x00, 0x00, 0x00,
            0xe6, 0x51, 0x06, 0x25, 0x81, 0x48, 0xa9, 0x44, 0xa7, 0xe3, 0x30,
            0x38, 0x65, 0x66, 0x76, 0x88, 0x0f, 0xed, 0xec, 0x6f, 0x72, 0x89,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        crypt.Encrypt(out.begin() + 3, data.begin(), 22);

        ASSERT_EQ(expected, out);
    }

    {
        std::array<uint8_t, 5> key = { 0x01, 0x02, 0x03, 0x04, 0x05 };

        Arc4Crypt crypt(key.begin(), key.end());

        std::array<uint8_t, 47> out = {};

        std::array<uint8_t, 47> expected =
        {
            0x00, 0x00, 0x00,
            0xe6, 0x51, 0x06, 0x25, 0x81, 0x48, 0xa9, 0x44, 0xa7, 0xe3, 0x30,
            0x38, 0x65, 0x66, 0x76, 0x88, 0x0f, 0xed, 0xec, 0x6f, 0x72, 0x89,
            0xef, 0xa5, 0xfa, 0xe4, 0x6c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        crypt.Encrypt(out.begin() + 3, data.begin(), 27);

        ASSERT_EQ(expected, out);
    }

    {
        std::array<uint8_t, 5> key = { 0x01, 0x02, 0x03, 0x04, 0x05 };

        Arc4Crypt crypt(key.begin(), key.end());

        std::array<uint8_t, 44> out = {};
        std::array<uint8_t, 44> expected = {};

        crypt.Encrypt(out.begin() + 3, data.begin(), 0);

        ASSERT_EQ(expected, out);
    }
}

TEST(Arc4CryptTests, DecryptOutIteratorUsageTest)
{
    const std::array<uint8_t, 14> data = { 0x45, 0xA0, 0x1F, 0x64, 0x5F, 0xC3, 0x5B,
                                           0x38, 0x35, 0x52, 0x54, 0x4B, 0x9B, 0xF5 };
    const std::vector<uint8_t> key = StrToU8Vec("Secret");

    {
        Arc4Crypt crypt(key.begin(), key.end());

        std::array<uint8_t, 17> out = {};

        std::array<uint8_t, 17> expected =
        {
            0x00, 0x00, 0x00,
            'A', 't', 't', 'a', 'c', 'k', ' ', 'a', 't', ' ', 'd', 'a',
            0x00, 0x00
        };

        crypt.Decrypt(out.begin() + 3, data.begin(), 12);

        ASSERT_EQ(expected, out);
    }

    {
        Arc4Crypt crypt(key.begin(), key.end());

        std::array<uint8_t, 17> out = {};

        std::array<uint8_t, 17> expected =
        {
            0x00, 0x00, 0x00,
            'A', 't', 't', 'a', 'c', 'k', ' ',
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        crypt.Decrypt(out.begin() + 3, data.begin(), 7);

        ASSERT_EQ(expected, out);
    }

    {
        Arc4Crypt crypt(key.begin(), key.end());

        std::array<uint8_t, 14> out = {};
        std::array<uint8_t, 14> expected = {};

        crypt.Decrypt(out.begin() + 3, data.begin(), 0);

        ASSERT_EQ(expected, out);
    }
}
