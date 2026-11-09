//! `receipt-registry`: a write-once public registry of receipt hashes for the
//! "Attested" project (verifiable receipts for private AI).
//!
//! A receipt hash is the SHA-256 (64 lowercase hex chars) of a receipt that lives
//! off-chain. Anchoring it here proves *who* registered that exact hash and *when*
//! (NEAR block time), and lets anybody check the receipt against the chain later.
//!
//! Design rules, on purpose:
//! - Immutable by design: there is no owner, no admin, no upgrade and no delete
//!   function. Nobody can remove or rewrite a record, including the contract's
//!   deployer. Once a hash is registered it stays exactly as it was written.
//! - First come, first served, once per hash: a second registration of the same
//!   hash always panics with `already registered`, even from the original submitter.
//!   (So the on-chain record binds the first submitter; verifiers must also compare
//!   `model_id` and `attestation_digest` of the record with the receipt they hold.)
//! - The caller pays for the storage they use: the attached deposit must cover
//!   `storage_byte_cost * bytes_added`; the excess is refunded to the caller. The
//!   contract never pays for storage from its own balance, so storage spam cannot
//!   drain it. (The first call is charged for the contract's state key too.)

use near_sdk::store::IterableMap;
use near_sdk::{AccountId, BorshStorageKey, Promise, env, near, require};

/// A `receipt_hash` or `attestation_digest` is a SHA-256: exactly this many hex chars.
const HEX_LEN: usize = 64;
const MAX_MODEL_ID_BYTES: usize = 128;
const DEFAULT_LIST_LIMIT: u64 = 50;
const MAX_LIST_LIMIT: u64 = 100;

const EVENT_STANDARD: &str = "attested_receipts";
const EVENT_VERSION: &str = "1.0.0";

/// One anchored receipt. Stored with borsh, returned to callers as JSON.
#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    /// Account that registered the hash (the predecessor of the call).
    pub submitter: AccountId,
    /// Model identifier as reported by the attestation, e.g. "openai/gpt-oss-120b".
    pub model_id: String,
    /// SHA-256 (64 lowercase hex chars) of the attestation evidence.
    pub attestation_digest: String,
    /// NEAR block timestamp in MILLISECONDS since the Unix epoch.
    pub timestamp_ms: u64,
}

#[near(serializers = [borsh])]
#[derive(BorshStorageKey)]
enum StorageKey {
    Receipts,
}

#[near(contract_state)]
pub struct ReceiptRegistry {
    /// receipt_hash -> Receipt. Iterates in registration order (nothing is ever removed).
    receipts: IterableMap<String, Receipt>,
}

impl Default for ReceiptRegistry {
    fn default() -> Self {
        Self {
            receipts: IterableMap::new(StorageKey::Receipts),
        }
    }
}

/// Body of the `EVENT_JSON:` log line (NEP-297 shape, our own standard name).
#[near(serializers = [json])]
struct EventLog {
    standard: String,
    version: String,
    event: String,
    data: Vec<ReceiptRegisteredEvent>,
}

#[near(serializers = [json])]
struct ReceiptRegisteredEvent {
    receipt_hash: String,
    submitter: AccountId,
    model_id: String,
    attestation_digest: String,
    timestamp_ms: u64,
}

fn is_lowercase_hex_64(s: &str) -> bool {
    s.len() == HEX_LEN && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[near]
impl ReceiptRegistry {
    /// Anchors a receipt hash on chain. Callable once per hash.
    ///
    /// Attach a deposit to pay for storage. Measured on a local sandbox: about 0.0034 NEAR
    /// for a typical call (0.0040 NEAR for the very first call on a fresh contract, which
    /// also creates the contract's state key). Worst case (128-byte `model_id`, 64-char
    /// submitter account, first call) is about 0.0053 NEAR, so 0.01 NEAR is always enough.
    /// Whatever is not needed is refunded to the caller.
    ///
    /// Panics (nothing is stored) if: `receipt_hash` or `attestation_digest` is not
    /// exactly 64 lowercase hex chars, `model_id` is empty / longer than 128 bytes /
    /// contains control characters, the hash is already registered, or the attached
    /// deposit is below the storage cost.
    #[payable]
    pub fn register_receipt(
        &mut self,
        receipt_hash: String,
        model_id: String,
        attestation_digest: String,
    ) -> Receipt {
        require!(
            is_lowercase_hex_64(&receipt_hash),
            "invalid receipt_hash: must be exactly 64 lowercase hex characters [0-9a-f]"
        );
        require!(
            is_lowercase_hex_64(&attestation_digest),
            "invalid attestation_digest: must be exactly 64 lowercase hex characters [0-9a-f]"
        );
        require!(!model_id.is_empty(), "invalid model_id: must not be empty");
        require!(
            model_id.len() <= MAX_MODEL_ID_BYTES,
            "invalid model_id: must be at most 128 bytes"
        );
        require!(
            !model_id.chars().any(char::is_control),
            "invalid model_id: must not contain control characters"
        );
        require!(
            !self.receipts.contains_key(&receipt_hash),
            "already registered"
        );

        let submitter = env::predecessor_account_id();
        let receipt = Receipt {
            submitter: submitter.clone(),
            model_id,
            attestation_digest,
            timestamp_ms: env::block_timestamp() / 1_000_000,
        };

        // Storage accounting. Nothing has been written yet in this call.
        let usage_before = env::storage_usage();
        self.receipts.insert(receipt_hash.clone(), receipt.clone());
        // `store` collections cache writes until they are dropped; push them to storage
        // now, and write the contract state key too, so the measurement below sees
        // every byte this call adds (the runtime would otherwise write them after we return).
        self.receipts.flush();
        env::state_write(&*self);
        let bytes_added = env::storage_usage().saturating_sub(usage_before);

        let required = env::storage_byte_cost().saturating_mul(u128::from(bytes_added));
        let attached = env::attached_deposit();
        require!(
            attached >= required,
            format!(
                "attached deposit {} yoctoNEAR is less than the required {} yoctoNEAR \
                 (storage cost of {} bytes)",
                attached.as_yoctonear(),
                required.as_yoctonear(),
                bytes_added
            )
        );
        let refund = attached.saturating_sub(required);
        if !refund.is_zero() {
            Promise::new(submitter).transfer(refund).detach();
        }

        let event = EventLog {
            standard: EVENT_STANDARD.to_string(),
            version: EVENT_VERSION.to_string(),
            event: "receipt_registered".to_string(),
            data: vec![ReceiptRegisteredEvent {
                receipt_hash,
                submitter: receipt.submitter.clone(),
                model_id: receipt.model_id.clone(),
                attestation_digest: receipt.attestation_digest.clone(),
                timestamp_ms: receipt.timestamp_ms,
            }],
        };
        let json = near_sdk::serde_json::to_string(&event)
            .unwrap_or_else(|_| env::panic_str("cannot serialize event"));
        env::log_str(&format!("EVENT_JSON:{json}"));

        receipt
    }

    /// The record for `receipt_hash`, or `null` if it was never registered.
    pub fn get_receipt(&self, receipt_hash: String) -> Option<Receipt> {
        self.receipts.get(&receipt_hash).cloned()
    }

    pub fn is_registered(&self, receipt_hash: String) -> bool {
        self.receipts.contains_key(&receipt_hash)
    }

    pub fn total_receipts(&self) -> u64 {
        u64::from(self.receipts.len())
    }

    /// Records in registration order as `[receipt_hash, record]` pairs.
    /// `from_index` defaults to 0, `limit` defaults to 50 and is capped at 100.
    pub fn list_receipts(
        &self,
        from_index: Option<u64>,
        limit: Option<u64>,
    ) -> Vec<(String, Receipt)> {
        let from = from_index.unwrap_or(0);
        if from >= self.total_receipts() {
            return Vec::new();
        }
        let limit = limit.unwrap_or(DEFAULT_LIST_LIMIT).min(MAX_LIST_LIMIT);
        // `from < len <= u32::MAX`, so the casts below cannot truncate.
        self.receipts
            .iter()
            .skip(from as usize)
            .take(limit as usize)
            .map(|(hash, receipt)| (hash.clone(), receipt.clone()))
            .collect()
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::NearToken;
    use near_sdk::mock::MockAction;
    use near_sdk::test_utils::{VMContextBuilder, accounts, get_logs};
    use near_sdk::testing_env;

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const DIGEST: &str = "f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1";
    const MODEL: &str = "openai/gpt-oss-120b";
    /// Plenty for any call: the real requirement is about 0.0035 NEAR.
    const BIG_DEPOSIT: NearToken = NearToken::from_millinear(10);

    fn set_context(predecessor: AccountId, deposit: NearToken) {
        let mut builder = VMContextBuilder::new();
        builder
            .current_account_id(accounts(0))
            .signer_account_id(predecessor.clone())
            .predecessor_account_id(predecessor)
            .attached_deposit(deposit)
            // 1_700_000_000_123 ms expressed in nanoseconds
            .block_timestamp(1_700_000_000_123_456_789);
        testing_env!(builder.build());
    }

    /// Like `set_context`, but first wipes the mocked blockchain's storage (it otherwise
    /// survives `testing_env!`), so a brand-new contract really starts empty.
    fn fresh_context(predecessor: AccountId, deposit: NearToken) {
        near_sdk::mock::with_mocked_blockchain(|b| {
            b.take_storage();
        });
        set_context(predecessor, deposit);
    }

    fn register(contract: &mut ReceiptRegistry, hash: &str) -> Receipt {
        contract.register_receipt(hash.to_string(), MODEL.to_string(), DIGEST.to_string())
    }

    /// Storage cost in yoctoNEAR of what `register_receipt` adds, as the contract measures it.
    fn measured_storage_cost(contract: &mut ReceiptRegistry, hash: &str) -> u128 {
        let before = env::storage_usage();
        register(contract, hash);
        u128::from(env::storage_usage() - before) * env::storage_byte_cost().as_yoctonear()
    }

    #[test]
    fn register_get_is_registered_total() {
        set_context(accounts(1), BIG_DEPOSIT);
        let mut contract = ReceiptRegistry::default();
        assert_eq!(contract.total_receipts(), 0);
        assert!(!contract.is_registered(HASH_A.to_string()));
        assert_eq!(contract.get_receipt(HASH_A.to_string()), None);

        let returned = register(&mut contract, HASH_A);
        let expected = Receipt {
            submitter: accounts(1),
            model_id: MODEL.to_string(),
            attestation_digest: DIGEST.to_string(),
            timestamp_ms: 1_700_000_000_123,
        };
        assert_eq!(returned, expected);
        assert_eq!(contract.get_receipt(HASH_A.to_string()), Some(expected));
        assert!(contract.is_registered(HASH_A.to_string()));
        assert!(!contract.is_registered(HASH_B.to_string()));
        assert_eq!(contract.total_receipts(), 1);

        register(&mut contract, HASH_B);
        assert_eq!(contract.total_receipts(), 2);
    }

    #[test]
    fn json_shape_of_receipt() {
        set_context(accounts(1), BIG_DEPOSIT);
        let mut contract = ReceiptRegistry::default();
        let receipt = register(&mut contract, HASH_A);
        let json = near_sdk::serde_json::to_value(&receipt).unwrap();
        assert_eq!(
            json,
            near_sdk::serde_json::json!({
                "submitter": accounts(1).to_string(),
                "model_id": MODEL,
                "attestation_digest": DIGEST,
                "timestamp_ms": 1_700_000_000_123u64,
            })
        );
    }

    #[test]
    #[should_panic(expected = "already registered")]
    fn duplicate_registration_from_other_account_panics() {
        set_context(accounts(1), BIG_DEPOSIT);
        let mut contract = ReceiptRegistry::default();
        register(&mut contract, HASH_A);
        set_context(accounts(2), BIG_DEPOSIT);
        register(&mut contract, HASH_A);
    }

    #[test]
    #[should_panic(expected = "already registered")]
    fn duplicate_registration_from_same_account_panics() {
        set_context(accounts(1), BIG_DEPOSIT);
        let mut contract = ReceiptRegistry::default();
        register(&mut contract, HASH_A);
        register(&mut contract, HASH_A);
    }

    #[test]
    fn duplicate_registration_leaves_first_record_unchanged() {
        set_context(accounts(1), BIG_DEPOSIT);
        let mut contract = ReceiptRegistry::default();
        let first = register(&mut contract, HASH_A);
        set_context(accounts(2), BIG_DEPOSIT);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            contract.register_receipt(HASH_A.to_string(), "other".to_string(), HASH_B.to_string())
        }));
        assert!(result.is_err());
        assert_eq!(contract.get_receipt(HASH_A.to_string()), Some(first));
        assert_eq!(contract.total_receipts(), 1);
    }

    fn assert_rejected(hash: &str, model: &str, digest: &str, expected_msg: &str) {
        set_context(accounts(1), BIG_DEPOSIT);
        let mut contract = ReceiptRegistry::default();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            contract.register_receipt(hash.to_string(), model.to_string(), digest.to_string())
        }));
        let err = result.expect_err("registration should have panicked");
        let msg = err
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| err.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default();
        assert!(
            msg.contains(expected_msg),
            "panic message {msg:?} lacks {expected_msg:?}"
        );
        assert_eq!(
            contract.total_receipts(),
            0,
            "nothing may be stored on a rejected call"
        );
    }

    #[test]
    fn bad_receipt_hash_is_rejected() {
        let msg = "invalid receipt_hash";
        assert_rejected("", MODEL, DIGEST, msg);
        assert_rejected(&HASH_A[..63], MODEL, DIGEST, msg); // too short
        assert_rejected(&format!("{HASH_A}a"), MODEL, DIGEST, msg); // too long
        assert_rejected(&HASH_A.to_uppercase(), MODEL, DIGEST, msg); // uppercase hex
        assert_rejected(&format!("{}g", &HASH_A[..63]), MODEL, DIGEST, msg); // non-hex char
        assert_rejected(&format!("0x{}", &HASH_A[..62]), MODEL, DIGEST, msg); // 0x prefix
        assert_rejected(&format!(" {}", &HASH_A[..63]), MODEL, DIGEST, msg); // whitespace
    }

    #[test]
    fn bad_attestation_digest_is_rejected() {
        let msg = "invalid attestation_digest";
        assert_rejected(HASH_A, MODEL, "", msg);
        assert_rejected(HASH_A, MODEL, &DIGEST[..63], msg);
        assert_rejected(HASH_A, MODEL, &DIGEST.to_uppercase(), msg);
        assert_rejected(HASH_A, MODEL, &format!("{}z", &DIGEST[..63]), msg);
    }

    #[test]
    fn bad_model_id_is_rejected() {
        assert_rejected(HASH_A, "", DIGEST, "invalid model_id: must not be empty");
        assert_rejected(HASH_A, &"m".repeat(129), DIGEST, "at most 128 bytes");
        // 65 two-byte characters are 130 bytes but only 65 chars: the limit is in bytes.
        assert_rejected(HASH_A, &"é".repeat(65), DIGEST, "at most 128 bytes");
        assert_rejected(HASH_A, "bad\nmodel", DIGEST, "control characters");
        assert_rejected(HASH_A, "bad\u{0}model", DIGEST, "control characters");
        assert_rejected(HASH_A, "bad\u{7f}model", DIGEST, "control characters");
        assert_rejected(HASH_A, "bad\u{85}model", DIGEST, "control characters");
    }

    #[test]
    fn model_id_limits_are_accepted() {
        set_context(accounts(1), BIG_DEPOSIT);
        let mut contract = ReceiptRegistry::default();
        let max = "m".repeat(128);
        contract.register_receipt(HASH_A.to_string(), max.clone(), DIGEST.to_string());
        assert_eq!(
            contract.get_receipt(HASH_A.to_string()).unwrap().model_id,
            max
        );
        // quotes, slashes, unicode and spaces are fine (the event is JSON-escaped)
        contract.register_receipt(
            HASH_B.to_string(),
            "a \"quoted\" модель/1".to_string(),
            DIGEST.to_string(),
        );
        let logs = get_logs();
        let event: near_sdk::serde_json::Value = near_sdk::serde_json::from_str(
            logs.last().unwrap().strip_prefix("EVENT_JSON:").unwrap(),
        )
        .expect("event must be valid JSON even with quotes in model_id");
        assert_eq!(event["data"][0]["model_id"], "a \"quoted\" модель/1");
    }

    #[test]
    #[should_panic(expected = "less than the required")]
    fn zero_deposit_is_rejected() {
        set_context(accounts(1), NearToken::from_yoctonear(0));
        let mut contract = ReceiptRegistry::default();
        register(&mut contract, HASH_A);
    }

    #[test]
    fn insufficient_deposit_message_states_required_and_attached() {
        // Find out what a call really costs, then attach exactly one yocto less.
        fresh_context(accounts(1), BIG_DEPOSIT);
        let required = measured_storage_cost(&mut ReceiptRegistry::default(), HASH_A);
        assert!(required > 0);

        fresh_context(accounts(1), NearToken::from_yoctonear(required - 1));
        let mut contract = ReceiptRegistry::default();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            register(&mut contract, HASH_A)
        }));
        let err = result.expect_err("one yocto short must be rejected");
        let msg = err.downcast_ref::<String>().cloned().unwrap_or_default();
        assert!(
            msg.contains(&format!("attached deposit {} yoctoNEAR", required - 1)),
            "{msg}"
        );
        assert!(
            msg.contains(&format!("required {required} yoctoNEAR")),
            "{msg}"
        );
    }

    #[test]
    fn exact_deposit_is_accepted_and_nothing_is_refunded() {
        fresh_context(accounts(1), BIG_DEPOSIT);
        let required = measured_storage_cost(&mut ReceiptRegistry::default(), HASH_A);

        fresh_context(accounts(1), NearToken::from_yoctonear(required));
        let mut contract = ReceiptRegistry::default();
        register(&mut contract, HASH_A);
        assert!(near_sdk::test_utils::get_created_receipts().is_empty());
    }

    #[test]
    fn excess_deposit_is_refunded_to_caller() {
        fresh_context(accounts(2), BIG_DEPOSIT);
        let required = measured_storage_cost(&mut ReceiptRegistry::default(), HASH_A);
        // sanity: the documented "about 0.0035 NEAR" and "0.01 NEAR is enough" claims
        assert!(required < BIG_DEPOSIT.as_yoctonear());
        assert!(required > NearToken::from_millinear(3).as_yoctonear());

        fresh_context(accounts(2), BIG_DEPOSIT);
        let mut contract = ReceiptRegistry::default();
        register(&mut contract, HASH_A);

        let receipts = near_sdk::test_utils::get_created_receipts();
        assert_eq!(receipts.len(), 1, "exactly one refund receipt");
        assert_eq!(receipts[0].receiver_id, accounts(2));
        assert_eq!(receipts[0].actions.len(), 1);
        match &receipts[0].actions[0] {
            MockAction::Transfer { deposit, .. } => {
                assert_eq!(
                    deposit.as_yoctonear(),
                    BIG_DEPOSIT.as_yoctonear() - required
                );
            }
            other => panic!("expected a Transfer action, got {other:?}"),
        }
    }

    #[test]
    fn storage_is_charged_per_record_and_state_key_only_once() {
        set_context(accounts(1), BIG_DEPOSIT);
        let mut contract = ReceiptRegistry::default();
        let first = measured_storage_cost(&mut contract, HASH_A);
        let second = measured_storage_cost(&mut contract, HASH_B);
        let third = measured_storage_cost(&mut contract, &"c".repeat(64));
        assert!(
            first > second,
            "the first call also pays for the contract state key"
        );
        assert_eq!(second, third, "same-size records cost the same");
    }

    #[test]
    fn longer_model_id_costs_proportionally_more() {
        set_context(accounts(1), BIG_DEPOSIT);
        let mut contract = ReceiptRegistry::default();
        measured_storage_cost(&mut contract, HASH_A); // pay the one-off state key first
        let short = measured_storage_cost(&mut contract, HASH_B);
        let before = env::storage_usage();
        contract.register_receipt("d".repeat(64), "m".repeat(100), DIGEST.to_string());
        let long =
            u128::from(env::storage_usage() - before) * env::storage_byte_cost().as_yoctonear();
        let extra_chars = 100 - MODEL.len() as u128;
        // model_id is stored once in the record: each extra byte costs exactly one byte of storage
        assert_eq!(
            long - short,
            extra_chars * env::storage_byte_cost().as_yoctonear()
        );
    }

    #[test]
    fn worst_case_cost_is_below_documented_upper_bound() {
        // Longest model_id and longest possible account id (64 chars).
        let long_account: AccountId = format!("{}.near", "a".repeat(59)).parse().unwrap();
        assert_eq!(long_account.as_str().len(), 64);
        set_context(long_account, BIG_DEPOSIT);
        let mut contract = ReceiptRegistry::default();
        // the very first call is the most expensive one (state key included)
        let cost = measured_storage_cost_with(&mut contract, HASH_A, &"m".repeat(128));
        println!("worst-case first-call storage cost: {cost} yoctoNEAR");
        assert!(
            cost < NearToken::from_millinear(10).as_yoctonear(),
            "worst case {cost}"
        );
        assert!(
            cost < NearToken::from_millinear(6).as_yoctonear(),
            "worst case {cost}"
        );
    }

    fn measured_storage_cost_with(contract: &mut ReceiptRegistry, hash: &str, model: &str) -> u128 {
        let before = env::storage_usage();
        contract.register_receipt(hash.to_string(), model.to_string(), DIGEST.to_string());
        u128::from(env::storage_usage() - before) * env::storage_byte_cost().as_yoctonear()
    }

    #[test]
    fn event_log_has_standard_shape() {
        set_context(accounts(1), BIG_DEPOSIT);
        let mut contract = ReceiptRegistry::default();
        register(&mut contract, HASH_A);
        let logs = get_logs();
        assert_eq!(logs.len(), 1);
        let expected = format!(
            "EVENT_JSON:{{\"standard\":\"attested_receipts\",\"version\":\"1.0.0\",\
             \"event\":\"receipt_registered\",\"data\":[{{\"receipt_hash\":\"{HASH_A}\",\
             \"submitter\":\"{}\",\"model_id\":\"{MODEL}\",\"attestation_digest\":\"{DIGEST}\",\
             \"timestamp_ms\":1700000000123}}]}}",
            accounts(1)
        );
        assert_eq!(logs[0], expected);
    }

    #[test]
    fn rejected_call_emits_no_event() {
        set_context(accounts(1), BIG_DEPOSIT);
        let mut contract = ReceiptRegistry::default();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            contract.register_receipt("bad".to_string(), MODEL.to_string(), DIGEST.to_string())
        }));
        assert!(get_logs().is_empty());
    }

    fn hash_n(n: u64) -> String {
        format!("{n:064x}")
    }

    #[test]
    fn pagination() {
        set_context(accounts(1), BIG_DEPOSIT);
        let mut contract = ReceiptRegistry::default();
        assert!(contract.list_receipts(None, None).is_empty());
        for n in 0..120 {
            if n % 20 == 0 {
                // the mocked chain caps total log size per "transaction"; start a new one
                set_context(accounts(1), BIG_DEPOSIT);
            }
            contract.register_receipt(hash_n(n), MODEL.to_string(), DIGEST.to_string());
        }
        assert_eq!(contract.total_receipts(), 120);

        // default limit is 50, order is registration order
        let page = contract.list_receipts(None, None);
        assert_eq!(page.len(), 50);
        assert_eq!(page[0].0, hash_n(0));
        assert_eq!(page[49].0, hash_n(49));
        assert_eq!(page[0].1.submitter, accounts(1));

        // explicit window
        let page = contract.list_receipts(Some(10), Some(5));
        let hashes: Vec<_> = page.iter().map(|(h, _)| h.clone()).collect();
        assert_eq!(hashes, (10..15).map(hash_n).collect::<Vec<_>>());

        // limit is capped at 100
        assert_eq!(contract.list_receipts(Some(0), Some(1000)).len(), 100);
        // last, partial page
        let page = contract.list_receipts(Some(100), Some(50));
        assert_eq!(page.len(), 20);
        assert_eq!(page[19].0, hash_n(119));
        // out of range and zero limit
        assert!(contract.list_receipts(Some(120), None).is_empty());
        assert!(contract.list_receipts(Some(u64::MAX), None).is_empty());
        assert!(contract.list_receipts(Some(0), Some(0)).is_empty());
        // walking page by page visits every record exactly once
        let mut seen = Vec::new();
        let mut from = 0;
        loop {
            let page = contract.list_receipts(Some(from), Some(33));
            if page.is_empty() {
                break;
            }
            from += page.len() as u64;
            seen.extend(page.into_iter().map(|(h, _)| h));
        }
        assert_eq!(seen, (0..120).map(hash_n).collect::<Vec<_>>());
    }
}
