use std::fs;

use cggmp24::key_share::AnyKeyShare; // trait providing shared_public_key()
use cggmp24::{
    DataToSign, ExecutionId, PartialSignature, PregeneratedPrimes, aux_info_gen, keygen,
    security_level::SecurityLevel128, supported_curves::Secp256k1,
};
use rand::rngs::OsRng;
use round_based::sim;

mod ppd_serializer;

fn main() {
    presignature_serde_sim_example();
}

#[allow(dead_code)]
fn basic_sim_example() {
    let n: u16 = 3;
    let eid = ExecutionId::new(b"demo eid");
    // Run keygen for all n parties
    let incomplete = sim::run(n, |i, party| {
        let eid = eid;
        async move {
            cggmp24::keygen::<Secp256k1>(eid, i, n)
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
            let primes = cggmp24::PregeneratedPrimes::<SecurityLevel128>::generate(&mut OsRng);
            cggmp24::aux_info_gen(eid, i, n, primes)
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
        .map(|(k, a)| cggmp24::KeyShare::from_parts((k, a)).unwrap())
        .collect();

    // Sign with all parties (n-of-n)
    let msg = DataToSign::digest::<sha2::Sha256>(b"hello");
    let signature = sim::run(n, |i, party| {
        let eid = ExecutionId::new(b"sign eid");
        let key_share = key_shares[i as usize].clone();
        async move {
            cggmp24::signing(eid, i, &(0..n).collect::<Vec<u16>>(), &key_share)
                .sign(&mut OsRng, party, &msg)
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

#[allow(dead_code)]
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
        .map(|(k, a)| cggmp24::KeyShare::from_parts((k, a)).unwrap())
        .collect();

    // 4) Generate presignatures (all 3 parties)
    let eid_presig = ExecutionId::new(b"presig-3of3");
    let presigs = sim::run(n, |i, party| {
        let eid = eid_presig;
        let key_share = key_shares[i as usize].clone();
        async move {
            let mut rng = OsRng;
            cggmp24::signing(eid, i, &participants, &key_share)
                .generate_presignature(&mut rng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();
    let commitment = presigs[0].1.clone(); // same for all parties; just take from first

    // 5) Message to sign
    let msg = DataToSign::digest::<sha2::Sha256>(b"hello 3-of-3");

    // 6) Issue partial signatures
    let partials: Vec<_> = presigs
        .into_iter()
        .map(|presig| presig.0.issue_partial_signature(msg))
        .collect();

    // 7) Combine to full signature
    let sig =
        PartialSignature::combine(&partials, &commitment, msg).expect("invalid partial signatures");

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

    // Save auxiliary info to file (MessagePack)
    let aux_bytes = rmp_serde::to_vec(&aux).expect("serialize aux to msgpack");
    fs::write("aux_info.msgpack", aux_bytes).expect("write aux_info.msgpack");

    // Load auxiliary info from file (MessagePack)
    let aux_file_content = fs::read("aux_info.msgpack").expect("read aux_info.msgpack");
    let aux_loaded: Vec<cggmp24::key_share::AuxInfo<SecurityLevel128>> =
        rmp_serde::from_slice(&aux_file_content).expect("deserialize aux from msgpack");

    // 3) Complete key shares
    let key_shares: Vec<_> = incomplete
        .into_iter()
        .zip(aux_loaded)
        .map(|(k, a)| cggmp24::KeyShare::from_parts((k, a)).unwrap())
        .collect();

    // Save key shares to file (MessagePack)
    let key_shares_bytes =
        rmp_serde::to_vec_named(&key_shares).expect("serialize key_shares to msgpack");
    fs::write("key_shares.msgpack", key_shares_bytes).expect("write key_shares.msgpack");

    // Load key shares from file (MessagePack)
    let key_shares_file_content = fs::read("key_shares.msgpack").expect("read key_shares.msgpack");
    let key_shares_loaded: Vec<cggmp24::key_share::KeyShare<Secp256k1, SecurityLevel128>> =
        rmp_serde::from_slice(&key_shares_file_content)
            .expect("deserialize key_shares from msgpack");

    // 4) Generate presignatures (all 3 parties)
    let eid_presig = ExecutionId::new(b"presig-3of3");
    let presigs = sim::run(n, |i, party| {
        let eid = eid_presig;
        let key_share = key_shares_loaded[i as usize].clone();
        async move {
            let mut rng = OsRng;
            cggmp24::signing(eid, i, &participants, &key_share)
                .generate_presignature(&mut rng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    let commitment = presigs[0].1.clone(); // same for all parties; just take from first
    let presig_only: Vec<cggmp24::signing::Presignature<Secp256k1>> =
        presigs.into_iter().map(|(presig, _)| presig).collect();

    // Save presignatures to file (MessagePack)
    let presigs_bytes = rmp_serde::to_vec(&presig_only).expect("serialize presigs to msgpack");
    fs::write("presignatures.msgpack", presigs_bytes).expect("write presignatures.msgpack");

    // Save presignature public data using custom serializer wrapper
    let commitment_bytes = ppd_serializer::encode_ppd_msgpack(&commitment)
        .expect("serialize presignature public data to msgpack");
    fs::write("presignature_public.msgpack", commitment_bytes)
        .expect("write presignature_public.msgpack");

    // Load presignatures from file (MessagePack)
    let presigs_file_content =
        fs::read("presignatures.msgpack").expect("read presignatures.msgpack");
    let presig_only_loaded: Vec<cggmp24::signing::Presignature<Secp256k1>> =
        rmp_serde::from_slice(&presigs_file_content).expect("deserialize presigs from msgpack");

    // Load presignature public data from file using custom serializer wrapper
    let commitment_file_content =
        fs::read("presignature_public.msgpack").expect("read presignature_public.msgpack");
    let commitment = ppd_serializer::decode_ppd_msgpack::<Secp256k1>(&commitment_file_content)
        .expect("deserialize presignature public data from msgpack");

    // 5) Message to sign
    let msg = DataToSign::digest::<sha2::Sha256>(b"hello 3-of-3");

    // 6) Issue partial signatures
    let partials: Vec<_> = presig_only_loaded
        .into_iter()
        .map(|presig| presig.issue_partial_signature(msg))
        .collect();

    // 7) Combine to full signature
    let sig =
        PartialSignature::combine(&partials, &commitment, msg).expect("invalid partial signatures");

    // 8) Verify against the shared public key
    let public_key = key_shares_loaded[0].shared_public_key();
    sig.verify(&public_key, &msg)
        .expect("signature verify failed");

    println!("OK: signature verified. r={:?}, s={:?}", sig.r, sig.s);
}

#[allow(dead_code)]
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
