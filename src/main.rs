use std::fs;

use cggmp21::key_share::AnyKeyShare; // trait providing shared_public_key()
use cggmp21::{
    DataToSign, ExecutionId, PartialSignature, PregeneratedPrimes, aux_info_gen, keygen,
    security_level::SecurityLevel128, signing, supported_curves::Secp256k1,
};
use rand::rngs::OsRng;
use round_based::sim;

fn main() {
    presignature_serde_sim_example();
}

fn basic_sim_example() {
    let n: u16 = 3;
    let eid = ExecutionId::new(b"demo eid");
    // Run keygen for all n parties
    let incomplete = sim::run(n, |i, party| {
        let eid = eid;
        async move {
            cggmp21::keygen::<Secp256k1>(eid, i, n)
                .start(&mut OsRng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    // Normally you'd also run aux-info first; here we shortcut with trusted dealer style completion:
    // (For real usage run aux_info_gen first; see next snippet.)
    let aux = sim::run(n, |i, party| {
        let eid = ExecutionId::new(b"aux eid");
        async move {
            let primes = cggmp21::PregeneratedPrimes::<SecurityLevel128>::generate(&mut OsRng);
            cggmp21::aux_info_gen(eid, i, n, primes)
                .start(&mut OsRng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    let key_shares: Vec<_> = incomplete
        .into_iter()
        .zip(aux)
        .map(|(k, a)| cggmp21::KeyShare::from_parts((k, a)).unwrap())
        .collect();

    // Sign with all parties (n-of-n)
    let msg = DataToSign::digest::<sha2::Sha256>(b"hello");
    let signature = sim::run(n, |i, party| {
        let eid = ExecutionId::new(b"sign eid");
        let key_share = key_shares[i as usize].clone();
        async move {
            cggmp21::signing(eid, i, &(0..n).collect::<Vec<u16>>(), &key_share)
                .sign(&mut OsRng, party, msg)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec()
    .remove(0); // every party outputs the same signature

    // Retrieve shared public key (same for all parties)
    let public_key = key_shares[0].shared_public_key();
    match signature.verify(public_key.as_ref(), &msg) {
        Ok(()) => println!(
            "Signature verified.\nr={:?}, s={:?}",
            signature.r, signature.s
        ),
        Err(e) => println!("Signature verification FAILED: {e}"),
    }
}

fn presignature_sim_example() {
    let n: u16 = 3;
    let participants: [u16; 3] = [0, 1, 2];

    // 1) Keygen (n-of-n; no threshold set)
    let eid_keygen = ExecutionId::new(b"keygen-3of3");
    let incomplete = sim::run(n, |i, party| {
        let eid = eid_keygen;
        async move {
            let mut rng = OsRng;
            keygen::<Secp256k1>(eid, i, n).start(&mut rng, party).await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    // 2) Aux info
    let eid_aux = ExecutionId::new(b"aux-3of3");
    let aux = sim::run(n, |i, party| {
        let eid = eid_aux;
        async move {
            let mut rng = OsRng;
            let primes = PregeneratedPrimes::<SecurityLevel128>::generate(&mut rng);
            aux_info_gen(eid, i, n, primes).start(&mut rng, party).await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    // 3) Complete key shares
    let key_shares: Vec<_> = incomplete
        .into_iter()
        .zip(aux)
        .map(|(k, a)| cggmp21::KeyShare::from_parts((k, a)).unwrap())
        .collect();

    // 4) Generate presignatures (all 3 parties)
    let eid_presig = ExecutionId::new(b"presig-3of3");
    let presigs = sim::run(n, |i, party| {
        let eid = eid_presig;
        let key_share = key_shares[i as usize].clone();
        async move {
            let mut rng = OsRng;
            signing(eid, i, &participants, &key_share)
                .generate_presignature(&mut rng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    // 5) Message to sign
    let msg = DataToSign::digest::<sha2::Sha256>(b"hello 3-of-3");

    // 6) Issue partial signatures
    let partials: Vec<_> = presigs
        .into_iter()
        .map(|presig| presig.issue_partial_signature(msg))
        .collect();

    // 7) Combine to full signature
    let sig = PartialSignature::combine(&partials).expect("invalid partial signatures");

    // 8) Verify against the shared public key
    let public_key = key_shares[0].shared_public_key();
    sig.verify(&public_key, &msg)
        .expect("signature verify failed");

    println!("OK: signature verified. r={:?}, s={:?}", sig.r, sig.s);
}

fn presignature_serde_sim_example() {
    let n: u16 = 3;
    let participants: [u16; 3] = [0, 1, 2];

    // 1) Keygen (n-of-n; no threshold set)
    let eid_keygen = ExecutionId::new(b"keygen-3of3");
    let incomplete = sim::run(n, |i, party| {
        let eid = eid_keygen;
        async move {
            let mut rng = OsRng;
            keygen::<Secp256k1>(eid, i, n).start(&mut rng, party).await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    // 2) Aux info
    let eid_aux = ExecutionId::new(b"aux-3of3");
    let aux = sim::run(n, |i, party| {
        let eid = eid_aux;
        async move {
            let mut rng = OsRng;
            let primes = PregeneratedPrimes::<SecurityLevel128>::generate(&mut rng);
            aux_info_gen(eid, i, n, primes).start(&mut rng, party).await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    // Save auxiliary info to file (JSON)
    let aux_json = serde_json::to_string_pretty(&aux).expect("serialize aux to json");
    fs::write("aux_info.json", aux_json).expect("write aux_info.json");

    // Load auxiliary info from file (JSON)
    let aux_file_content = fs::read_to_string("aux_info.json").expect("read aux_info.json");
    let aux_loaded: Vec<cggmp21::key_share::AuxInfo<SecurityLevel128>> =
        serde_json::from_str(&aux_file_content).expect("deserialize aux from json");

    // 3) Complete key shares
    let key_shares: Vec<_> = incomplete
        .into_iter()
        .zip(aux_loaded)
        .map(|(k, a)| cggmp21::KeyShare::from_parts((k, a)).unwrap())
        .collect();

    // Save key shares to file (JSON)
    let key_shares_json =
        serde_json::to_string_pretty(&key_shares).expect("serialize key_shares to json");
    fs::write("key_shares.json", key_shares_json).expect("write key_shares.json");

    // Load key shares from file (JSON)
    let key_shares_file_content =
        fs::read_to_string("key_shares.json").expect("read key_shares.json");
    let key_shares_loaded: Vec<cggmp21::key_share::KeyShare<Secp256k1, SecurityLevel128>> =
        serde_json::from_str(&key_shares_file_content).expect("deserialize key_shares from json");

    // 4) Generate presignatures (all 3 parties)
    let eid_presig = ExecutionId::new(b"presig-3of3");
    let presigs = sim::run(n, |i, party| {
        let eid = eid_presig;
        let key_share = key_shares_loaded[i as usize].clone();
        async move {
            let mut rng = OsRng;
            signing(eid, i, &participants, &key_share)
                .generate_presignature(&mut rng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    // Save presignatures to file (JSON)
    let presigs_json = serde_json::to_string_pretty(&presigs).expect("serialize presigs to json");
    fs::write("presignatures.json", presigs_json).expect("write presignatures.json");

    // Load presignatures from file (JSON)
    let presigs_file_content =
        fs::read_to_string("presignatures.json").expect("read presignatures.json");
    let presigs_loaded: Vec<cggmp21::Presignature<Secp256k1>> =
        serde_json::from_str(&presigs_file_content).expect("deserialize presigs from json");

    // 5) Message to sign
    let msg = DataToSign::digest::<sha2::Sha256>(b"hello 3-of-3");

    // 6) Issue partial signatures
    let partials: Vec<_> = presigs_loaded
        .into_iter()
        .map(|presig| presig.issue_partial_signature(msg))
        .collect();

    // 7) Combine to full signature
    let sig = PartialSignature::combine(&partials).expect("invalid partial signatures");

    // 8) Verify against the shared public key
    let public_key = key_shares_loaded[0].shared_public_key();
    sig.verify(&public_key, &msg)
        .expect("signature verify failed");

    println!("OK: signature verified. r={:?}, s={:?}", sig.r, sig.s);
}

fn keygen_sim_example() {
    let n: u16 = 3; // number of parties
    let t: u16 = 2; // threshold (t-out-of-n)
    let eid = ExecutionId::new(b"demo-keygen-2025-09-14"); // unique per run

    // Run N parties locally; `i` is the party index (0..n-1), `party` is the simulated network handle
    let shares = sim::run(n, move |i, party| {
        let eid = eid; // ExecutionId is Copy; capture by value into the async closure
        async move {
            let mut rng = OsRng; // per-party RNG
            keygen::<Secp256k1>(eid, i, n)
                .set_threshold(t)
                .start(&mut rng, party)
                .await
        }
    })
    .unwrap() // simulation infra succeeded
    .expect_ok() // all parties returned Ok(...)
    .into_vec(); // Vec<IncompleteKeyShare>

    println!("DKG finished; produced {} incomplete shares.", shares.len());
}
