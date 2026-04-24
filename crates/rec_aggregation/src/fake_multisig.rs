use crate::AggregatedXMSS;

use leansig_wrapper::{MESSAGE_LENGTH, XmssPublicKey, XmssSignature};
use rand::{Rng, SeedableRng};
use sha3::Digest;
use std::{sync::OnceLock, time::Duration};

pub type Encoded = Vec<u8>;

pub struct Config {
    proof_size: u32,
    aggregate_time: Duration,
    verify_time: Duration,
}
impl Config {
    pub fn get() -> &'static Option<Config> {
        static CONFIG: OnceLock<Option<Config>> = OnceLock::new();
        CONFIG.get_or_init(|| {
            std::env::var("FAKE_MULTISIG").ok().and_then(|s| {
                let s: Vec<_> = s.split(',').collect();
                if s.len() == 3 {
                    match (s[0].parse::<u32>(), s[1].parse::<u64>(), s[2].parse::<u64>()) {
                        (Ok(proof_size), Ok(aggregate_time_ms), Ok(verify_time_ms)) => {
                            return Some(Config {
                                proof_size,
                                aggregate_time: Duration::from_millis(aggregate_time_ms),
                                verify_time: Duration::from_millis(verify_time_ms),
                            });
                        }
                        _ => {}
                    }
                }
                println!("FAKE_MULTISIG=proof_size,aggregate_time_ms,validate_time_ms");
                None
            })
        })
    }

    pub fn aggregate(
        &self,
        children: &[(&[XmssPublicKey], AggregatedXMSS)],
        raw_xmss: Vec<(XmssPublicKey, XmssSignature)>,
        message: &[u8; MESSAGE_LENGTH],
        slot: u32,
        log_inv_rate: usize,
    ) -> (Vec<XmssPublicKey>, AggregatedXMSS) {
        let mut sorted_keys: Vec<_> = children
            .iter()
            .flat_map(|(ks, _)| ks.iter().cloned())
            .chain(raw_xmss.iter().map(|(k, _)| k.clone()))
            .collect();
        sorted_keys.sort();
        sorted_keys.dedup();

        let mut hasher = sha3::Sha3_256::default();
        hasher.update(children.len().to_be_bytes());
        for (keys, proof) in children {
            for key in *keys {
                hasher.update(leansig_wrapper::xmss_public_key_to_ssz(key));
            }
            hasher.update(proof.serialize());
        }
        for (key, signature) in &raw_xmss {
            hasher.update(leansig_wrapper::xmss_public_key_to_ssz(key));
            hasher.update(leansig_wrapper::xmss_signature_to_ssz(signature));
        }
        hasher.update(raw_xmss.len().to_be_bytes());
        hasher.update(message);
        hasher.update(slot.to_be_bytes());
        hasher.update(log_inv_rate.to_be_bytes());

        let mut rng = rand::rngs::Xoshiro256PlusPlus::from_seed(hasher.finalize().into());
        let mut encoded = vec![0; self.proof_size as usize];
        rng.fill_bytes(&mut encoded);

        std::thread::sleep(self.aggregate_time);

        (sorted_keys, AggregatedXMSS::fake(encoded))
    }

    pub fn verify(&self) {
        std::thread::sleep(self.verify_time);
    }
}
