//! Supports importing PKCS12 objects into a YubiKey

use log::{error, info};
use rsa::pkcs1::RsaPrivateKey;

use const_oid::db::rfc5912::{ID_CE_KEY_USAGE, ID_CE_SUBJECT_ALT_NAME};
use der::Decode;
use x509_cert::{
    ext::pkix::{name::GeneralName, KeyUsage, KeyUsages, SubjectAltName},
    Certificate,
};
use yubikey::{
    certificate::CertInfo,
    piv::{import_rsa_key, AlgorithmId, RetiredSlotId, RsaKeyData, SlotId, SlotId::KeyManagement},
    PinPolicy, TouchPolicy, YubiKey,
};

use crate::misc::p12::process_p12;
use crate::Error::BadInput;
use crate::{Error, Result};

//------------------------------------------------------------------------------------
// Local methods
//------------------------------------------------------------------------------------
/// get_slot_from_sig_or_auth_cert inspects the KeyUsage and SubjectAltName extensions to determine
/// which slot a key should be imported into. This function MUST only be used with signature or
/// authentication certificates (the slot for decryption certificates is determined by the order
/// of appearance in the plist). If key usage does not feature DigitalSignature, Error::BadInput is
/// returned. If DigitalSignature is present, SubjectAltName is inspected. If an OtherName value is
/// present, SlotId::Authentication is returned, if not SlotId::Signature or an error is returned.
fn get_slot_from_sig_or_auth_cert(cert: &Certificate) -> Result<SlotId> {
    if Ok(true) != check_digital_signature(cert) {
        error!("Certificate did not contain KeyUsage with DigitalSignature so SlotId could not be determined");
        return Err(BadInput);
    }

    match san_has_other_name(cert) {
        Ok(true) => Ok(SlotId::Authentication),
        Ok(false) => Ok(SlotId::Signature),
        Err(e) => Err(e),
    }
}

/// san_has_other_name returns true if a SubjectAltName extension is present (and can be parsed) and
/// contains an OtherName value and false if OtherName is not present. If the SAN extension cannot be
/// parsed an error is returned. Only the first appearance of SubjectAltName is inspected.
fn san_has_other_name(cert: &Certificate) -> Result<bool> {
    if let Some(exts) = &cert.tbs_certificate.extensions {
        for ext in exts {
            if ext.extn_id == ID_CE_SUBJECT_ALT_NAME {
                let san = SubjectAltName::from_der(ext.extn_value.as_bytes())?;
                for gn in san.0.iter() {
                    if let GeneralName::OtherName(_on) = gn {
                        return Ok(true);
                    }
                }
                return Ok(false);
            }
        }
    }
    Ok(false)
}

/// check_key_usage takes a certificate and a key usage value and returns true if a KeyUsage extension
/// is present that contains that value and false otherwise. If KeyUsage extension cannot be parsed
/// or is no KeyUsage extension is present, an error is returned.
fn check_key_usage(cert: &Certificate, ku_to_check: KeyUsages) -> Result<bool> {
    if let Some(exts) = &cert.tbs_certificate.extensions {
        for ext in exts {
            if ext.extn_id == ID_CE_KEY_USAGE {
                let ku = KeyUsage::from_der(ext.extn_value.as_bytes())?;
                return Ok(ku.0.contains(ku_to_check));
            }
        }
    }
    error!("key usage extension is missing");
    Err(Error::KeyUsageMissing)
}

/// check_digital_signature takes a certificate returns true if a KeyUsage extension is present that
/// contains DigitalSignature and false otherwise. If KeyUsage extension cannot be parsed or is no
/// KeyUsage extension is present, an error is returned.
fn check_digital_signature(cert: &Certificate) -> Result<bool> {
    check_key_usage(cert, KeyUsages::DigitalSignature)
}

/// check_key_encipherment takes a certificate returns true if a KeyUsage extension is present that
/// contains KeyEncipherment and false otherwise. If KeyUsage extension cannot be parsed or is no
/// KeyUsage extension is present, an error is returned.
fn check_key_encipherment(cert: &Certificate) -> Result<bool> {
    check_key_usage(cert, KeyUsages::KeyEncipherment)
}

//------------------------------------------------------------------------------------
// Public methods
//------------------------------------------------------------------------------------
/// Gets a SlotId from the index of a given PKCS 12 object within a configuration profile. The
/// following logic is used:
///   - When index is 0, KeyManagement is used (i.e., the current decryption key)
///   - When index is > 0 and < 20, the 0x81 is added to index to determine slot
///   - For all other values, R20 is returned (the highest retired slot)
///
/// This function assumes that the certificate has already been analyzed to determine it is not a
/// signature cert or authentication cert.
pub(crate) fn get_slot_from_index(index: u8) -> SlotId {
    if 0 == index {
        KeyManagement
    } else {
        let rs: RetiredSlotId = (index + 0x81).try_into().unwrap_or(RetiredSlotId::R20);
        SlotId::Retired(rs)
    }
}

/// Writes the key and certificate extracted from `enc_p12` to the indicated YubiKey and slot
/// (if provided). If not slot is provided, the key usage and subject alt name extensions are
/// considered. Where key usage is signature, if the SAN has an OtherName, PIV slot is used else
/// signature slot is used. For key encipherment, the index is applied to the list of retired slots.
pub(crate) async fn import_p12(
    yubikey: &mut YubiKey,
    enc_p12: &[u8],
    password: &str,
    recovered_index: u8,
    slot_id: Option<SlotId>,
) -> Result<Vec<u8>> {
    let (der_cert, der_key) = process_p12(enc_p12, password, true)?;
    let cert = match Certificate::from_der(&der_cert) {
        Ok(cert) => yubikey::certificate::Certificate { cert },
        Err(e) => return Err(Error::Asn1(e)),
    };

    let der_key = match der_key {
        Some(dk) => dk,
        None => return Err(BadInput),
    };

    let slot = match slot_id {
        Some(s) => s,
        None => match check_key_encipherment(&cert.cert) {
            Ok(true) => get_slot_from_index(recovered_index),
            Ok(false) => match get_slot_from_sig_or_auth_cert(&cert.cert) {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to determine type of certificate from PKCS #12 object: {e:?}");
                    return Err(Error::ParseError);
                }
            },
            Err(e) => {
                error!("Failed to determine type of certificate from PKCS #12 object: {e:?}");
                return Err(Error::ParseError);
            }
        },
    };

    let rpk = match RsaPrivateKey::from_der(&der_key) {
        Ok(rpk) => rpk,
        Err(e) => {
            error!("Failed to parse RSA key from PKCS #12 object for {slot} slot: {e:?}");
            return Err(Error::Asn1(e));
        }
    };

    let rkd = match RsaKeyData::new(rpk.prime1.as_bytes(), rpk.prime2.as_bytes()) {
        Ok(rkd) => rkd,
        Err(e) => {
            error!("Failed to instantiate new RSA key object from PKCS #12 for {slot} slot: {e}");
            return Err(Error::ParseError);
        }
    };
    if let Err(e) = import_rsa_key(
        yubikey,
        slot,
        AlgorithmId::Rsa2048,
        rkd,
        TouchPolicy::Default,
        PinPolicy::Default,
    ) {
        error!(
            "Failed to import RSA key from PKCS #12 object into slot {slot}: {:?}",
            e
        );
        return Err(Error::YubiKey(e));
    }

    if let Err(e) = cert.write(yubikey, slot, CertInfo::Uncompressed) {
        error!(
            "Failed to import certificate from PKCS #12 object into slot {slot}: {:?}",
            e
        );
        return Err(Error::YubiKey(e));
    }

    info!("Installed PKCS #12 into {slot} slot");
    Ok(der_cert)
}

//------------------------------------------------------------------------------------
// Unit tests
//------------------------------------------------------------------------------------
#[test]
fn categorize_sig_cert() {
    use hex_literal::hex;
    let der_cert = hex!("308204CB308203B3A00302010202027DBE300D06092A864886F70D01010B0500305D310B300906035504061302555331183016060355040A0C0F552E532E20476F7665726E6D656E74310C300A060355040B0C03446F44310C300A060355040B0C03504B493118301606035504030C0F444F442050422053572043412D3533301E170D3233313031383133333033355A170D3234313230333233353935395A3074310B300906035504061302555331183016060355040A130F552E532E20476F7665726E6D656E74310C300A060355040B1303446F44310C300A060355040B1303504B49310D300B060355040B1304444953413120301E06035504031317544553545245434F564552592E3535353737373930303130820122300D06092A864886F70D01010105000382010F003082010A0282010100EB14BCC59FE75921214D3EC6252707FE2E378740F0B4E461D524431B2CD17B3798F70B55758AAFC7F2D933C0E21EA02A4C86789B39365783E802EFECD82B50BEB49F883D6867F0952778793169AC17098ED34A01216C233D2EC448247E1E1AAFDEC9F71343D8A4C8D0873A34EF890EB79D7FE79FD1A590033D17E8688C8E2A3195CF5CECEBFFEBBA792BA3D4D69F1BD3E83703B3FE6CD8F0AF2CC77B4A17DEB9213F84EE4BB6182C9AF4421B259344D1D8ECBE6B64704F9E8B1FB9D3F60100027D7470583A0B9C68F70017272A89D99A7DDA4B738D97D3A615067EF956C9F578282349B9886E6818075B61EE19922A14179FF0ABCA0B77720206C89547885E1B0203010001A382017C30820178301F0603551D2304183016801461BF1745A00B56DC28F3EEC5FB6DA305C3B5F48C301D0603551D0E0416041472C597DA026D3D85F887EFE25A6D374FCCE511F6300E0603551D0F0101FF0404030206C0301D0603551D250416301406082B0601050507030206082B0601050507030430160603551D20040F300D300B0609608648016502010B2730200603551D11041930178115746573747265636F7665727940746573742E636F6D30818306082B0601050507010104773075304306082B060105050730028637687474703A2F2F706263726C2E726564686F756E64736F6674776172652E6E65742F7369676E2F444F445042535743415F35332E636572302E06082B060105050730018622687474703A2F2F70626F6373702E726564686F756E64736F6674776172652E6E657430470603551D1F0440303E303CA03AA0388636687474703A2F2F706263726C2E726564686F756E64736F6674776172652E6E65742F63726C2F444F445042535743415F35332E63726C300D06092A864886F70D01010B0500038201010067FC5378B6E820F9D2DE5E50442DF9EAF5E54CEA4CCECFF0180304E841B83B95A42CF1CCAACF629AD6C582B5EC2ACF060C0017F5311AB9FA632DE2C0E18DF75BD958A847E42C7971AEC2DBD3844BC56D64FE677FAB26013BCE533B7967CE68A34B0C5D39D7DEEFC3BC0E2C1B29EB79A833606B1D1DC9C75DD5ADC21341B178E2F4BDA6AF9DB1176D084E8CD5D8EA5B373D6563B65AB392D102CCAD4790DB45A3C2476054B7946AC678F2FE2A04E1464F2A3A356547FA2C5B4E7F898244BF5B011F62EFFE63F03E86E83A70EF78787B06B401A9D51C2274D3BB34CC62899F588C3FBF23D6143A4884461F4ECE71D841C48C22D78B46B3C34CDE0731A1645D9F64");
    let cert = Certificate::from_der(&der_cert).unwrap();
    let slot_id = get_slot_from_sig_or_auth_cert(&cert).unwrap();
    assert_eq!(SlotId::Signature, slot_id);
}

#[test]
fn categorize_auth_cert() {
    use hex_literal::hex;
    let der_cert = hex!("308204DC308203C4A00302010202027DBF300D06092A864886F70D01010B0500305D310B300906035504061302555331183016060355040A0C0F552E532E20476F7665726E6D656E74310C300A060355040B0C03446F44310C300A060355040B0C03504B493118301606035504030C0F444F442050422053572043412D3533301E170D3233313031383133333033355A170D3234313230333233353935395A3074310B300906035504061302555331183016060355040A130F552E532E20476F7665726E6D656E74310C300A060355040B1303446F44310C300A060355040B1303504B49310D300B060355040B1304444953413120301E06035504031317544553545245434F564552592E3535353737373930303130820122300D06092A864886F70D01010105000382010F003082010A0282010100B2AF3A4E20ADE62DB4E6E5ED659DFEEA0C11A1AEFD9C78AAD8EC899EB480F8659EAB1BFCBDBDE0F9E3577625D09273AEC88D466CBE5C18700049FB430260FEE89937FCFEA144CD249D4FBF0675792A9CB8FF7F684A16E251813AFA3E71C48B6A6F0BC03A50384170409D9049CF8B1845F1AFF4D4C5EE028AD70E3A41289E163872498267C2A5C41BB6781BDBF2F21C226A826E0BEE03A864E31A931244ABDAF4EBB3D756D394E8A1EDD8A7F29A44FF777736D22CC140275C53C9E41ABB6DC6F56852AC9C4C033FAAE6B52BBF3412C8C239BF758502ABBCED126CF679EA19CFA83125B7AF82F57D74920B22E634C1A56ABFBFA8A06BCE6186E8907405A4EFBF590203010001A382018D30820189301F0603551D2304183016801461BF1745A00B56DC28F3EEC5FB6DA305C3B5F48C301D0603551D0E04160414E7D4591A11A2E5482E2BC4AAA692BCD211A37C50300E0603551D0F0101FF040403020780301F0603551D250418301606082B06010505070302060A2B06010401823714020230160603551D20040F300D300B0609608648016502010B27302F0603551D1104283026A024060A2B060104018237140203A0160C1435353537373739303031383731383731406D696C30818306082B0601050507010104773075304306082B060105050730028637687474703A2F2F706263726C2E726564686F756E64736F6674776172652E6E65742F7369676E2F444F445042535743415F35332E636572302E06082B060105050730018622687474703A2F2F70626F6373702E726564686F756E64736F6674776172652E6E657430470603551D1F0440303E303CA03AA0388636687474703A2F2F706263726C2E726564686F756E64736F6674776172652E6E65742F63726C2F444F445042535743415F35332E63726C300D06092A864886F70D01010B05000382010100AC376575B836F96A549592BD6290DBBBA26CFD7D712C3791D52A07B7497F62E7E21F150FF3843543ED8115A6EF76974274AA5DA1236CBEE489FAFB243A6753ABF907A3219877C5DF4BA5F6ACF0D24F2B94F4398CD6550DDAAC5D9CCBD5D973CCE0F199DB798FB8E4820A769AE676C2319C97D96CAE6A5F6E423286D17A803B004415FAB714F0EA29689B271D8453187B02B7AE5921077560D891D4C3A5429DCE7920EDE1D6B341FF0F81C22CF6E865D96AC7E5DC1640688C4283854CD93D2BAACF2523313676723FD78C232D3458C42DA9421DDFD4F0F55CCD3F360AB9DE7B4557CA21D67D24CDBEC51E99798127B014E72FABFAB175BAFA214B6AFBFB913BBD");
    let cert = Certificate::from_der(&der_cert).unwrap();
    let slot_id = get_slot_from_sig_or_auth_cert(&cert).unwrap();
    assert_eq!(SlotId::Authentication, slot_id);
}

#[test]
fn categorize_enc_cert() {
    use hex_literal::hex;
    let der_cert = hex!("308204D2308203BAA003020102020238AD300D06092A864886F70D01010B05003060310B300906035504061302555331183016060355040A0C0F552E532E20476F7665726E6D656E74310C300A060355040B0C03446F44310C300A060355040B0C03504B49311B301906035504030C12444F4420504220454D41494C2043412D3439301E170D3231313230343030303030305A170D3234313230333030303030305A3074310B300906035504061302555331183016060355040A130F552E532E20476F7665726E6D656E74310C300A060355040B1303446F44310C300A060355040B1303504B49310D300B060355040B1304444953413120301E06035504031317544553545245434F564552592E3535353737373930303130820122300D06092A864886F70D01010105000382010F003082010A0282010100B044E98CD6CDBD13DF642A80B4B46837ED5A496AE3949CFE93A432F039A3B402DB1469FF226AE9B9421C9F5341F0D15E35C8B1497AC889FBA8CD79496FE73EB8C1252D3D418B87BDC2947ABDDAEF05BF393733DD507AD3D3F90D417F32B67505507C06F00EFC9386521A2C7C1549C6554F348DCB427CB580E7809417E3AF30E891288129EB73A9724F9CB8B0F1E0FF241D87D06E9D6CB288011EA6257A5A5722BC06D3CE333A7EFBDF75692C0E5F310C66BFDC6C4B7A8D4286A725092A5B90F3A082F505D8B6E88AF2AD7B1AF995CD6259874251398F06963921423E64A5DD569F4B19E3DA061B285F9898BDC5A38322AD8192B332F7A48384EEE067F52DBDE90203010001A38201803082017C301F0603551D230418301680143D724DA9252F7029399078E0583C374C2BDF6EB1304A0603551D1F04433041303FA03DA03B8639687474703A2F2F706263726C2E726564686F756E64736F6674776172652E6E65742F63726C2F444F445042454D41494C43415F34392E63726C300E0603551D0F0101FF04040302052030160603551D20040F300D300B0609608648016502010B27301D0603551D0E041604140A60C77760FFF88115A79B2AB02C1C449906A5BC30818606082B06010505070101047A3078304606082B06010505073002863A687474703A2F2F706263726C2E726564686F756E64736F6674776172652E6E65742F7369676E2F444F445042454D41494C43415F34392E636572302E06082B060105050730018622687474703A2F2F70626F6373702E726564686F756E64736F6674776172652E6E657430200603551D11041930178115746573747265636F7665727940746573742E636F6D301B0603551D0904143012301006082B06010505070904310413025553300D06092A864886F70D01010B0500038201010052EBEE43C159A07E9E097063539701C593F0109BF384C1BAF15A01303A5245441FBF99C793316CB4ECF202E7C0E22C92E64CE3CE8A7685E5B9211E03B11B0FBBFF201F754352B784904FA88C97EE4BEFC50FBD3D09FCD6E761B08DC310092FE243CEE2040AFEBF569A3FFC5DB039E12C269DDB7FB1515263B81ABB926905CA5B0CDC729B0DD0035B4A740037BD76743D75103956B5C0CF55339A5E2F637C19FC89B2864DB7EC61E33650E7EF4AAF27FF5E020902FBF5A21DB0409FF90166B65047BAB03E45A7966A7564E010731BB2F8B467CB52796EBA69BA2FF28F762775C8541A1D35BEA396FAC95CBF753C2822B1432A7283ABB233722030F75C09724FF1");
    let cert = Certificate::from_der(&der_cert).unwrap();
    assert!(get_slot_from_sig_or_auth_cert(&cert).is_err());
    assert!(check_key_encipherment(&cert).unwrap());
}

// TODO: remove this when openssl is bumped beyond version 10.55
#[tokio::test]
async fn p12_test_rc2() {
    use hex_literal::hex;
    use openssl::pkcs12::Pkcs12;
    let enc_p12 = hex!("30820ADD02010330820AA706092A864886F70D010701A0820A9804820A9430820A903082054706092A864886F70D010706A0820538308205340201003082052D06092A864886F70D010701301C060A2A864886F70D010C0106300E04085F9CC1D47F0847980202080080820500BE1672279FB4C2DBEAA4BED11E3493FE5B046BD0E08C5ADCDB86FC3390CE2B30DD13C71CAFEC24E98122559F73C78A79E45DAC498AB4C935C368461828F51C54BA583DF8C85F6F84CC549313F0E1E2476E86FA1BA9DDC78FDF89B6342EE66BFD131CED48C0FB36C5ADC69CB34EDA1F2B0A4714954609B67959E92F44F81C726923D91D163232F59F8E90539AF10227898FA5ED5585CCD2275585AAF916988BB4B664203DB9EDEE463D62E06D5556C345E12564325F90E40414405E38EC7CF1F38607708001DDC569D32777DE5C86BF030FFC0567DB85F84A3DE013246B80FAF7AB2B59C87521EA93B61983C16198CC39EB94B6BDE0969A501A83452FF257AF7C62DDB137AE795905E3B3719104857A77751CB08A0432C7A0ECC0C9BFDE14882C416CC6D48AD9E4929E5112D7AEAD6ACADA729EC56D5EDB94217BD3E678B360CE634BDED2E6CF69E158E731D3204249CC331402B77A0804F961FCDEDDE0FA5A09EC6707EE7690D58C8AFBF6D5640E5725A5D9D1954B63FDE19D06F62083CB965A5E6AA5AE2A2CCA3622112B29846F080615358B6C34DD8C7C9251C5A7B8FCAFDC3ECE761E69118B70CE570B0FF6630295B6A80D12DB3EEE6905F81308A82F41C53FE74875FCDF99C99776BB234EAC1F5FCC7690E0B789050F0A0013FDE0B110B881E20297E287D7323FBC7CD02BC64EA112FA1A987A57219DDFDC38A6D58F2D4BC152603001BDBAEAE707CB7BCAB43630CFB8D584F2DF3375BA346AE38C2FFC99E652EC4249CD254D86DFB5297E713B8448FE5A3DDDDA0B8F44C505C4222BB3DFBF537506CF029A5D7D1C8284870C78DA50DF99B7A43A54438BEDACE209B727EAD15BA2B42E7471584FD841EAACBF64AD094C2CC83CB12400D34A9189D58363C07134A0DE499FAD578C49611721AF2439BEFBE52CD15C73D9B6ADBD37F7943BA81E38F6C40E10C22352C47BB64660CEBE12879040ED4D27F58A6272BB9BEB7B8FB90E3821E15A24FDE627978DBAB35516E389DA223DDE2149332233CD4C7DB5ABC409ED43211A307B366C494C6F7DDDD2C4C2C50E243A7FCFD82B572401280281F7EF737CFACD1EC5AE8F7EC1DF3E23161283317B629D14DD0AFDFA50DFE248E93CC05E363A3F6BDDC8E2787D56FEC64EC88F61400F4B37B2212F65BA8EA758EE177B06C47171C2AD982DDC17084AA4DA76C2855A322588954920086C0EE62D8ABF4D89A7CDBA6F7F496D8464BAED6B136028A63968D2B6C066F28105F0778C3C3DA012DA81C3CFBDE7ED9405EF4544CDFD6E636067DCABA3272BC845E0B4FC41644968B42BF447135EB17C96B7ECF0D1516CE9898EA092BE80AB995AB888F1877AD1E76607E4A3F637AE8DBDC38A129CF77042D9A82988BD2E147B957484AAFA81EE36A3E80B8B3EB80864298B9D0A9B102236FC4DCFED3F85FDC634EF65FCC5A6A6B3B9DD56540B0BED68C9ECBECA6AA81D02258D8668D0AB6DE6D8C23A7785BA15F5FFF7C6E59A149BD16BFDD15B084A8F7CE0BD4404BEF8D00302EFE25654821FAD16FE06DE02E22E8F81CF199AC2123492421BA8E1D5CAC474B6F8DE0FE694B8F4636081742D28704A748587BE1983227D4BF9C9BD157CEC8D43CDDA56EC5FEBB956E2F68107237510C80500886F3E7C66AC23B5336D74FD03CC5F0268A0948E29E33843EE34782F203262C21A832E241468CB98904C8999D73D815E62C44307353B9E5D6F6CCEC4EB1AB9BEAAE6FADAE167FC4CF004FEC0CA02F00AFA7DAE8B9E48E9E80A1E84A83BD9F1B18CB9DD832B2CBDE646DE3A9A80A5C20DDF8B3082054106092A864886F70D010701A08205320482052E3082052A30820526060B2A864886F70D010C0A0102A08204EE308204EA301C060A2A864886F70D010C0103300E04084780BFFC417A2B0D02020800048204C86C6774BD8693F0BC13C1AEC3B65FAF0F850FD3ACF61E57D52FA5EAA2BE90F88B252B98925F49DE0FFB2FACDAB6CE0A1E07B71C79D84C734EEEC6078AD5A9D11E3BC4839D47E85135A100584B0787D8EF21AF84205D7000E44F21DFEFE82FE155980BD1B441D31920761C4163588DF0E2C198C14DA10A277ECD7ACB93508010AD8D1D9E1504354FDCAADC04E30B92E969145BE5D00768B3F75CE98C4D004DF001C13CDFCAA4242E5E370A9C2E3FBD2C0F4BED0B25D7317F2AECDA466B40997C02E4579C3ED36CFE970B7D8CE0AF553135B03E72E2C106607946F239BEFC38FBF72F2B1554A5ACFC31C856791F51FD439E989B303EF95C26AD83AF009D56955F19DFB97B231DDBB28F757653BAA56C77779135737F0E37A7E8D7505B447050164E541C3231A95CBBC7A861E5A6CF4059992D00256A2D4946FBA0A4E7394011C2DEAC99B234F0C0BA8C4E00F98C5E9D37AC7A0AAA91350F6527D8609019F28CF0926D10A8EFAA2BFE33824893344C2E6E99AD510E7AEB6F0818B2536A2CFE24A4862172B5376C47B29DB247B9A762FE070BC87C9E41FD71A846210323681EB8B2F744605FAEE8EF0D81C5BAF47660CFFF301FA4CFD110D03B23B79084ACCB658A4EE464A8EFCD0D46B5E6444C92C87FC114420AA5B04F1D48EC61CBD455109B70D3B6D1C85F3390BA2622FE460235F9228EA6503F6867AFE1531C89EBC575F9CDE3147E4B5371DBBB49DF3EC99BDF156E45563267513A63A7208AF7842E740F81F25877A2F8CDE3C3CBB3922E042C5DE29F6B4F0406AB35990867930FE0D240898AA362A0D7D852421DC7B35291FD0333CE1B426E00D0A17231F01117B2258C4EAFAFE17E2BEB1A78085E198C2CEBB8E0E08CFE8623D68E04D406527BE09614F6B95FB28AFDC2146515C1549CAE9244AAE376FC2DC28057845CCDF31ED47F0073713422EB8F4E6336DA64749C7ADF2E1226348B41C8FC9DF2B1E279800FB4BD85B13115A41971873178A0C3F800BA3EABDD0CC014F32C4E2553D8AE92DF82D85A8E089C3F6F3C39C875932EFE982125AA3CDF0FCD47FA4C5661868BA987FC2169137F91FCDD85064DF2C2B844A24E75C8E1A0A2C294D91B9964D7AE2D7B29E5493DEAF1CCD0F9EB49FD1042EE442965A77329513471C527DA9115A9A77CA075A9789AA5951469683B1897B7C43D4322C4196911BBD370F1C9F540CD6DAD46854876E7C3EBD7E4593115DB0D32B3D783196B7CDC86589D72C766B80E82084E9948547CCC156383660884DDB9BEAB6EBE5642FDC0FEB0D802EBEC088DEF4460FCB13F3FE179BB755BD87B2759E6E284F4FAE4B11C548B1F4F6660F6250DE974118DDA9F4CD700ECFE8DF21635FA30511233964EE24D6A5EF3327B0AFE5674E9754DBFB41D03D4F95138F33EDA92A2C06DF440BDE203E913324B5F680647A61398C183B7A0483A59FFFBE45097234920A1D87114CF4325234DE439034CA0812C8CF3598439749F28672D85E57A6CCF348C550EC042FF8F510C9B3F784F2AD87C1FC7D73E30ADB99CCDF7BF7880F050BB8692EF573A4825E01D4E3E3CB5045A88123094ABA00CFB18A845849F28902C34F796ECE75D7345E9A407909F992B0FDA86A43EFBDA18A3E350AECA29E3130E5F29BE6BBC50FAC07CA497E152F66A0ABA4A604E1A8D1A50A336DB64409735D4ADEE668CC0D697B396DE418356B9400A755AAB5854C3D836FF40F0443125302306092A864886F70D0109153116041419E824599B0D0270784C8C7D69283125D08A388C302D3021300906052B0E03021A05000414D80BFC8A6B80CE7A34B472C1D773E7A34BDB2A7D04084638DF59B5266B17");
    let password = "HO@@Oy7.i8qMF|K[(\\'n";
    openssl::init();

    let pkcs12 = match Pkcs12::from_der(&enc_p12) {
        Ok(p) => p,
        Err(_e) => {
            panic!();
        }
    };

    let _p12 = match pkcs12.as_ref().parse2(password) {
        Ok(p12) => p12,
        Err(e) => {
            println!("p12_test_rc2 failed with: {e}. Make sure Cargo.lock has not rolled openssl, openssl-src and openssl-sys beyond 0.10.55, 111.26.0+1.1.1u and 0.9.90, respectively.");
            panic!();
        }
    };
}

#[tokio::test]
async fn p12_test_aes() {
    use hex_literal::hex;
    use openssl::pkcs12::Pkcs12;
    let enc_p12 = hex!("30820B8302010330820B3906092A864886F70D010701A0820B2A04820B2630820B22308205A406092A864886F70D010706A0820595308205910201003082058A06092A864886F70D010701304906092A864886F70D01050D303C301B06092A864886F70D01050C300E0408FA7D40B9169B79A602020800301D060960864801650304012A0410F69C01F6D951AC6C3FAA967C89F4D15180820530A30E254E45905608565834E9879EBEBB9DB3504875E8A188A006E7F2CB9AF1735DD7C2A48F94FE8C3925EB30938C51982BFADCC2AD3331C38CC034FA7D2BC4F587A3F6042E16044FAC4277B9E92972069E136E7993AB09B4F9D1F91120E1CD4BB9AF804BE656DC8302EAA18F7D7BD78856C411F177B63BE94BF688DC9BA31389265E0C27A7128D1C93396899F75D6446C9F2BFF26E36E0DA4D114BA4CEE2C3CA48840A9313F379E8DB6485B83FC28A6C91C708CDBFBBFDEB1CA56F4B382562EDEBC622AE730E39BA40102D57A9A8353D04BE1219CB255400404F39D7CA88FB56ED4D451B9F35E5B1B1384103E3F22EDD81B3380222FDF27E0F8586723332DFC10F4D9151E73DF8EDBFBE94723F8FF106CFB9E71BE9581EABB3CAE8B695F6C08569EBDCF45B281462D9C4163E09E380587FE8869275463FD8FA9A952EF5DE726CE992C14F3F4B7FDD14364E8E7005C5AC43F4D12950F7A988B5A6A06A932ED586DC853A854C8B74996391AF13FFD29500CE7C59F38200A329FF20345AC8066A9AB2EB65BB89652E2F9395363E766AED406742E16CDC8EB8CC7B8366737F18AA903EF9F359BDFD8A5F8FA23F1B5298E886CF735F8B955811627E1E769ACEECEE762C1F5C7A428026822250F06231541B107DC892A7730B3C9DB35092F469ACA0EC99572BE99B38EFD751673922FDB23E1139E0E138935501ADBC8AAD0A067CA99D75A1C0E159A7C01FF7ACEDDA89B3532A28D644755CB5EFFA579AC43DB77AEE75585ECE6777378934BEE5C7F19F3529740AE34862DA2DFCAB35727F93D595CCB51E3B8F8D9200F0365FE71872D5DFC279BBE6C8E6C6428144B3716FA25164D1A2193523F18ED33AD134994CD8F12AF8F3A16607087DD9D275A2F73EEEAEF370A2AC61BD74284F7EF0E61A874182FB61527A18837F2605D71F9D067F54EAF8172888B3F19CBB0011AD38B4ABC998F153646517AF2187BC21D81032747FEE17F455751EEE25863709D6C9B68BCCB805B70895A8CCDB280876857A10C401AB941EAB25E67A31FFD823191457E4F9395C13C3D0D9FF68FF47687D7A059C1FB6DEF0E82C21E74F6EE725FD3E44CF890107F32D4560024731200A3EE54FE03B624D960D65D027CAD834011EF2D3B4DB7CE3E5E8C7A457BC196A598704D42361F7C2DE2E48527E635002720EF738D3F6F471EEF4AF827B4AFD8B2EBBDCFE81FC3987730C458982265F0470A4480071C40D1D1C01538CDBFFFDD8C6399EF2E910C1063F71CDBF03499372864504D18F48A7754E356AE25CD413E22CF942C489E728623D9E6B7BDCC8F6E2B56C35127EEA4CE8EE08F0A1C7B4CE96845004C0A547DCB3D1E0FD07019FF56790994DEB1F6FAB8F1D9CA3F01356D14CBB900B03776F49C2731422ADD2227827ACF1A3B29DFD21F17BBC9FA4720F1BC206AF3FF171185DF3FE552013736EFB143FAE28BA414C55F8C047F76D3EF9977608D8A4B9A4735D5776416B8D35E6543AEC8CBF812DAE9A46E877FF27A205EBE1E2B0D0F442991D9A658728D15A113F122A54D4B489374A8C9552996D0B4ED9261330F2FCDC4942CC9F3DF16FE646C4B284BD40E2DB7AD0A06C94A5E5A743897AC33993710FEAB7367980DF31EAC898995B365B4DD5322227D6B0F511CA37AD7B03DF9795670C4F2FB6A41F45A7F1BD0099EEB10F7A5774AE157F973F7286B12A727EDB83E2A0D3019B06E3C16DA9E465CE2C2579079D9F1A3C312EC1152DB06311119667A1E7665DF96BD264573A10DEBF4FC94D39A215AB54A438D09EFB048D95EE816E79620DDFE55DBFFB09ECFA78F17E11880B3E4EB3165500EBDCA363D21646D2F4012C0AFA5A5452230049D19C5EF2AA0BA4DDB578715A3082057606092A864886F70D010701A0820567048205633082055F3082055B060B2A864886F70D010C0A0102A08205233082051F304906092A864886F70D01050D303C301B06092A864886F70D01050C300E04082081A49FD9DA41AE02020800301D060960864801650304012A04101275FC0451B14B3026556E076C3F9F2B048204D0A0BF38397A52EBF0473658A309C06ABCFC981478DC1D004BE0A2EA01653639D2C13C4DC6065F4F337A3ADD6919F436478B437C086F7A780CE432718EAAA02C7AA66F019CDF8662D59FDC0A03DD417916F9EF44556E547D1D3FF3181EDB6A92B596034F2293D64D46EBEFC3D0AFEBAC1636520B8235EDFC3C2E31E83E0C53DBFCF9EBC4283622159652AAD3086D3C106E02B2A0DA9E5D41136400E9C74CFB5B847919985619B6B47249D3FE3122DDBC03281458113800B5276273104225823115D1833B4BE8B82BDE2B3F8867F3FEA7664B8A8C30658911C24CFC5CA93DAC7B7DF2B2CC44D7963EA62F2C7190CE22FF5A915AB490796E9DE95E8DF4F03534ABEF116DBFF2CF21811DA450CFF4789AB61625E3C4EBF77FF9FB2EC4A68CA3988BF358711F3CF43A4DBFB6A4152557AF31599551AF636F9078097D542F154683171B43C73C27288CB604CFB39E0AC96CDEEB6293CBB6EEAFBD7FEA322E3C225C5281DF28BF4E2B23B2C1E2BD5761EED1283A52B279D49B5FB70E711095DF8470DCAE3ECCC48D8E0DFEA23050613A1D7299CB04CCBAE0F6F248899A61EA5E2A0F330B0247B6BD82163A2E17B016722450BF197F410EB55F873C89C12C4035090985FAF7FD2237F3B94313C847E6449B63BF30D8DE98232C88B22FCE7324B229BB3874EC8831411594EB72FEDC9F1DA1E43948C0EB20F3D5A6680DD19BC1163F33F78F832E07E49E4B80B6579085D66150A2003CB5CD5C8261C359DEE063783A089FDD4D9E9987DA6931DE4893290482900A6CDB05DB3F37F90CCB59F0EFA55F06D72E4FEBE5BE7E18E19B08476345DFF0C3D13BEB9B2ABA0F8D7932146829C09680AF6AE9818B115A083EA5B3E0E82BAB264B94BD9EBC081AA680EA7266C3192CCEC5B1FF8785C66D2881D9AB41806C7E1BD5FC9EB1319CC2FD3F40A01639C8D8DEF5862A6DFD95EADF043CA4A078FF79E3C3C90135786478CEF9063F9571E2793DA5694E17B6295A0497D5594F1C1FDB229B138B316028E1101E50972EFCFBD4ED5468E90543649988D8F31D7FBFB878C1F0CBAFA786C6D04E4B49251A7E35407B944260DE5CAA787E4143B1302C05C73453A45F60BC3A5FECE399CC3CB9DE361D6D70CDE106E019BF669956B446C4EF4D2B6082F5E8871380FA4AB252ED85B6B6BA8AE6DDE70ECA6E34037E032EBCE9E29059DC562BE9798B511F7B40A2C57969ECE60B86F643F14AC7CA30ADE96E54AFC614DFE9D54E25C0214098519686B0D8A512E68AC566AC8DD70C07F214AF907C0CAFDEEC0FB877D3D1974D4C9B34968436B2FE7805C7D0F446FD2D728C9A73CBCE52CD957CC149D789B25A40D1C9C6DA1679ABF743EA85EFEF9C5FC3A6FBE824A49C5EFBA2F5C9F0BE13095D60D2CBA576DD5325016D9073C055A7E63242A4C36392FE9BE289A4F8213D9CF538280878A986C98648A0B565017C15B743F0D04C66A9B2E630A039429A9B27C893B1E849B5D46A8130BD8F0DD2AF87DBD7B86B904688F31F1AF08A31DBBBC32E78FAC6551185124F6855C5D56CC7706D2B0497E78E97AAD59315E406C3B931394782393B55B2760581E5FD4A0F0734B90A5A18615AC37EA7BBBBA4E8C47BE32694AE2079667D4EE1D0E9E4A52A3E5CD0D413346C8E791DF2CE7C605C25686985F4C906A5AF2A3E94B36F1F6AD77ABC77E7C4548A1FF3D4A10FC7374D31BE6118B5F8CD6576DB4DEB115EAD726F89F29FC9F5E7109D3125302306092A864886F70D01091531160414A2CA7AC1AD901871268B987332C7DEFDC45367DA30413031300D060960864801650304020105000420CAC134A4727DADA8DAB3E49A032EE534BBA6DDFDC30FC4D11AC44A2D71258DB404080FC231E327069D8802020800");
    let password = "@7{Xv0{>H/=xP$i0ObTRVz|M4<wh+r3N&?4{b!l{RS!KYf&q/y_813d&skN,CE{WSA#til>?:cRLo9^=i_(BGfwf:L<~3o1p{$aO:dhm-|u58gOeJ^#RD.s9L\\&Eit#S";
    openssl::init();

    let pkcs12 = match Pkcs12::from_der(&enc_p12) {
        Ok(p) => p,
        Err(_e) => {
            panic!();
        }
    };

    let _p12 = match pkcs12.as_ref().parse2(password) {
        Ok(p12) => p12,
        Err(_e) => {
            panic!();
        }
    };
}
