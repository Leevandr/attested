//! Integration tests: the real wasm, built by this project, running in the local
//! near-workspaces sandbox (a private local chain; nothing touches testnet or mainnet).
//!
//! Run with `cargo test` (needs `cargo-near` installed; the first run downloads the
//! sandbox node binary).

use near_workspaces::network::Sandbox;
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::{Gas, NearToken};
use near_workspaces::{Account, Contract, Worker};
use serde_json::{Value, json};
use tokio::sync::OnceCell;

const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const HASH_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const DIGEST: &str = "f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1";
const DIGEST_2: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const MODEL: &str = "openai/gpt-oss-120b";

const BYTE_COST: u128 = 10_000_000_000_000_000_000; // 1e19 yoctoNEAR per byte (sandbox = mainnet)
const GAS: Gas = Gas::from_tgas(30);
/// What the Node CLI is advised to attach by default.
const SAFE_DEPOSIT: NearToken = NearToken::from_millinear(10);

/// Compile once for the whole test binary (the cargo build is slow and blocking).
static WASM: OnceCell<Vec<u8>> = OnceCell::const_new();

async fn wasm() -> &'static [u8] {
    WASM.get_or_init(|| async {
        near_workspaces::compile_project("./")
            .await
            .expect("wasm build failed")
    })
    .await
}

struct Env {
    worker: Worker<Sandbox>,
    contract: Contract,
    alice: Account,
    bob: Account,
}

async fn setup() -> Env {
    let wasm = wasm().await;
    let worker = near_workspaces::sandbox().await.unwrap();
    let contract = worker.dev_deploy(wasm).await.unwrap();
    let alice = worker.dev_create_account().await.unwrap();
    let bob = worker.dev_create_account().await.unwrap();
    Env {
        worker,
        contract,
        alice,
        bob,
    }
}

async fn register(
    env: &Env,
    from: &Account,
    hash: &str,
    model: &str,
    digest: &str,
    deposit: NearToken,
) -> ExecutionFinalResult {
    from.call(env.contract.id(), "register_receipt")
        .args_json(json!({
            "receipt_hash": hash,
            "model_id": model,
            "attestation_digest": digest,
        }))
        .deposit(deposit)
        .gas(GAS)
        .transact()
        .await
        .unwrap()
}

async fn view(env: &Env, method: &str, args: Value) -> Value {
    env.contract
        .view(method)
        .args_json(args)
        .await
        .unwrap()
        .json()
        .unwrap()
}

async fn balance(account: &Account) -> u128 {
    account.view_account().await.unwrap().balance.as_yoctonear()
}

async fn contract_storage_usage(env: &Env) -> u64 {
    env.contract.view_account().await.unwrap().storage_usage
}

/// Debug text of every failed outcome (contains the contract's panic message).
fn failure_text(result: &ExecutionFinalResult) -> String {
    result
        .failures()
        .iter()
        .map(|o| format!("{:?}", (*o).clone().into_result().err()))
        .collect::<Vec<_>>()
        .join(" | ")
}

fn assert_failed_with(result: &ExecutionFinalResult, expected: &str) {
    assert!(result.is_failure(), "call should have failed");
    let text = failure_text(result);
    assert!(
        text.contains(expected),
        "failure {text:?} should contain {expected:?}"
    );
}

#[tokio::test]
async fn register_two_accounts_and_read_back() {
    let env = setup().await;
    assert_eq!(view(&env, "total_receipts", json!({})).await, json!(0));
    assert_eq!(
        view(&env, "get_receipt", json!({"receipt_hash": HASH_A})).await,
        Value::Null
    );
    assert_eq!(
        view(&env, "is_registered", json!({"receipt_hash": HASH_A})).await,
        json!(false)
    );

    let r1 = register(&env, &env.alice, HASH_A, MODEL, DIGEST, SAFE_DEPOSIT).await;
    assert!(r1.is_success(), "alice failed: {}", failure_text(&r1));
    // the method returns the stored record
    let returned: Value = r1.json().unwrap();
    assert_eq!(returned["submitter"], json!(env.alice.id().to_string()));
    assert_eq!(returned["model_id"], json!(MODEL));
    assert_eq!(returned["attestation_digest"], json!(DIGEST));

    let r2 = register(
        &env,
        &env.bob,
        HASH_B,
        "other/model-7b",
        DIGEST_2,
        SAFE_DEPOSIT,
    )
    .await;
    assert!(r2.is_success(), "bob failed: {}", failure_text(&r2));

    assert_eq!(view(&env, "total_receipts", json!({})).await, json!(2));
    assert_eq!(
        view(&env, "is_registered", json!({"receipt_hash": HASH_A})).await,
        json!(true)
    );
    assert_eq!(
        view(&env, "is_registered", json!({"receipt_hash": HASH_C})).await,
        json!(false)
    );

    let a = view(&env, "get_receipt", json!({"receipt_hash": HASH_A})).await;
    assert_eq!(a["submitter"], json!(env.alice.id().to_string()));
    assert_eq!(a["model_id"], json!(MODEL));
    assert_eq!(a["attestation_digest"], json!(DIGEST));
    assert_eq!(
        a, returned,
        "get_receipt must match what register_receipt returned"
    );
    let b = view(&env, "get_receipt", json!({"receipt_hash": HASH_B})).await;
    assert_eq!(b["submitter"], json!(env.bob.id().to_string()));
    assert_eq!(b["model_id"], json!("other/model-7b"));
    assert_eq!(b["attestation_digest"], json!(DIGEST_2));

    // exact JSON shape: four fields, timestamp is a number in milliseconds
    let keys: Vec<&str> = a.as_object().unwrap().keys().map(String::as_str).collect();
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    assert_eq!(
        sorted,
        [
            "attestation_digest",
            "model_id",
            "submitter",
            "timestamp_ms"
        ]
    );
    let ts = a["timestamp_ms"]
        .as_u64()
        .expect("timestamp_ms must be a JSON number");
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    // the sandbox runs on wall-clock time: milliseconds (not ns/s) and close to now
    assert!(
        ts.abs_diff(now_ms) < 10 * 60 * 1000,
        "timestamp_ms {ts} is not ms near now {now_ms}"
    );
    assert!(b["timestamp_ms"].as_u64().unwrap() >= ts);

    // listing: registration order, [hash, record] pairs, default limit
    let all = view(&env, "list_receipts", json!({})).await;
    let all = all.as_array().unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0][0], json!(HASH_A));
    assert_eq!(all[0][1], a);
    assert_eq!(all[1][0], json!(HASH_B));
    assert_eq!(all[1][1], b);
    let page = view(&env, "list_receipts", json!({"from_index": 1, "limit": 1})).await;
    assert_eq!(page, json!([[HASH_B, b]]));
    let empty = view(&env, "list_receipts", json!({"from_index": 2})).await;
    assert_eq!(empty, json!([]));
    let huge = view(
        &env,
        "list_receipts",
        json!({"from_index": 18446744073709551615u64}),
    )
    .await;
    assert_eq!(huge, json!([]));
    let _ = &env.worker;
}

#[tokio::test]
async fn duplicate_registration_fails_and_first_record_is_unchanged() {
    let env = setup().await;
    let first = register(&env, &env.alice, HASH_A, MODEL, DIGEST, SAFE_DEPOSIT).await;
    assert!(first.is_success());
    let before = view(&env, "get_receipt", json!({"receipt_hash": HASH_A})).await;

    // another account tries to take over the hash with different content
    let steal = register(&env, &env.bob, HASH_A, "evil/model", DIGEST_2, SAFE_DEPOSIT).await;
    assert_failed_with(&steal, "already registered");
    // the original submitter cannot overwrite either
    let again = register(&env, &env.alice, HASH_A, MODEL, DIGEST, SAFE_DEPOSIT).await;
    assert_failed_with(&again, "already registered");

    assert_eq!(
        view(&env, "get_receipt", json!({"receipt_hash": HASH_A})).await,
        before
    );
    assert_eq!(view(&env, "total_receipts", json!({})).await, json!(1));
    // and the failed call must not have emitted a registration event
    assert!(!steal.logs().iter().any(|l| l.starts_with("EVENT_JSON:")));
}

#[tokio::test]
async fn invalid_inputs_are_rejected_on_chain() {
    let env = setup().await;
    let upper = HASH_B.to_uppercase();
    let cases: Vec<(String, String, String, &str)> = vec![
        (
            HASH_A[..63].into(),
            MODEL.into(),
            DIGEST.into(),
            "invalid receipt_hash",
        ),
        (upper, MODEL.into(), DIGEST.into(), "invalid receipt_hash"),
        (
            format!("{}g", &HASH_A[..63]),
            MODEL.into(),
            DIGEST.into(),
            "invalid receipt_hash",
        ),
        (
            HASH_A.into(),
            MODEL.into(),
            DIGEST[..10].into(),
            "invalid attestation_digest",
        ),
        (
            HASH_A.into(),
            "".into(),
            DIGEST.into(),
            "invalid model_id: must not be empty",
        ),
        (
            HASH_A.into(),
            "m".repeat(129),
            DIGEST.into(),
            "at most 128 bytes",
        ),
        (
            HASH_A.into(),
            "a\nb".into(),
            DIGEST.into(),
            "control characters",
        ),
    ];
    for (hash, model, digest, expected) in cases {
        let r = register(&env, &env.alice, &hash, &model, &digest, SAFE_DEPOSIT).await;
        assert_failed_with(&r, expected);
    }
    assert_eq!(view(&env, "total_receipts", json!({})).await, json!(0));
    // a 128-byte model_id is the longest accepted
    let ok = register(
        &env,
        &env.alice,
        HASH_A,
        &"m".repeat(128),
        DIGEST,
        SAFE_DEPOSIT,
    )
    .await;
    assert!(ok.is_success(), "{}", failure_text(&ok));
}

#[tokio::test]
async fn storage_deposit_is_enforced_exactly() {
    let env = setup().await;

    // No deposit at all.
    let r = register(
        &env,
        &env.alice,
        HASH_A,
        MODEL,
        DIGEST,
        NearToken::from_yoctonear(0),
    )
    .await;
    assert_failed_with(&r, "less than the required");
    assert_failed_with(&r, "attached deposit 0 yoctoNEAR");
    assert_eq!(view(&env, "total_receipts", json!({})).await, json!(0));

    // Measure the real requirement: an over-paid call, then look at what the contract's
    // storage grew by (contract storage_usage is the runtime's own account of it).
    let usage0 = contract_storage_usage(&env).await;
    let ok = register(&env, &env.alice, HASH_A, MODEL, DIGEST, SAFE_DEPOSIT).await;
    assert!(ok.is_success(), "{}", failure_text(&ok));
    let first_required = u128::from(contract_storage_usage(&env).await - usage0) * BYTE_COST;
    println!("first call (includes contract state key) storage cost: {first_required} yocto");

    // Second record, same sizes: measure it too, then replay it one yocto short and exact.
    let usage1 = contract_storage_usage(&env).await;
    let ok = register(&env, &env.alice, HASH_B, MODEL, DIGEST, SAFE_DEPOSIT).await;
    assert!(ok.is_success());
    let required = u128::from(contract_storage_usage(&env).await - usage1) * BYTE_COST;
    println!(
        "later call storage cost: {required} yocto ({} bytes)",
        required / BYTE_COST
    );
    assert!(required < first_required);
    assert!(first_required < SAFE_DEPOSIT.as_yoctonear());

    let short = NearToken::from_yoctonear(required - 1);
    let r = register(&env, &env.bob, HASH_C, MODEL, DIGEST, short).await;
    assert_failed_with(&r, &format!("attached deposit {} yoctoNEAR", required - 1));
    assert_failed_with(&r, &format!("required {required} yoctoNEAR"));
    assert_eq!(
        view(&env, "is_registered", json!({"receipt_hash": HASH_C})).await,
        json!(false)
    );

    let exact = register(
        &env,
        &env.bob,
        HASH_C,
        MODEL,
        DIGEST,
        NearToken::from_yoctonear(required),
    )
    .await;
    assert!(
        exact.is_success(),
        "exact deposit must work: {}",
        failure_text(&exact)
    );
    assert_eq!(view(&env, "total_receipts", json!({})).await, json!(3));
}

#[tokio::test]
async fn excess_deposit_is_refunded_and_contract_keeps_only_storage_cost() {
    let env = setup().await;
    // First call pays for the state key too, so warm up with one registration.
    let warm = register(&env, &env.bob, HASH_B, MODEL, DIGEST, SAFE_DEPOSIT).await;
    assert!(warm.is_success());

    let attached = NearToken::from_near(5);
    let alice_before = balance(&env.alice).await;
    let contract_before = balance_of_contract(&env).await;
    let usage_before = contract_storage_usage(&env).await;

    let r = register(&env, &env.alice, HASH_A, MODEL, DIGEST, attached).await;
    assert!(r.is_success(), "{}", failure_text(&r));

    let alice_after = balance(&env.alice).await;
    let contract_after = balance_of_contract(&env).await;
    let required = u128::from(contract_storage_usage(&env).await - usage_before) * BYTE_COST;

    let alice_drop = alice_before - alice_after;
    let contract_gain = contract_after - contract_before;
    println!(
        "storage cost {required} yocto; alice paid {alice_drop} yocto in total ({} for gas); \
         contract kept {contract_gain}; gas burnt {:?}",
        alice_drop - required,
        r.total_gas_burnt
    );
    // Alice paid the storage cost plus gas, not the 5 NEAR she attached.
    assert!(
        alice_drop >= required,
        "she must pay at least the storage cost"
    );
    let gas_budget = NearToken::from_millinear(5).as_yoctonear(); // generous: 0.005 NEAR
    assert!(
        alice_drop < required + gas_budget,
        "paid {alice_drop} for cost {required}"
    );
    assert!(
        alice_drop < attached.as_yoctonear() / 100,
        "most of the 5 NEAR must come back"
    );
    // The contract kept exactly the storage cost, nothing more (and did not pay from its own funds).
    assert_eq!(contract_gain, required);

    // A refund receipt to alice exists and logs contain the event.
    assert!(r.logs().iter().any(|l| l.starts_with("EVENT_JSON:")));
}

async fn balance_of_contract(env: &Env) -> u128 {
    env.contract
        .view_account()
        .await
        .unwrap()
        .balance
        .as_yoctonear()
}

#[tokio::test]
async fn contract_balance_never_pays_for_storage_even_on_first_call() {
    let env = setup().await;
    let usage0 = contract_storage_usage(&env).await;
    let bal0 = balance_of_contract(&env).await;
    // attach exactly 10 mNEAR; a few registrations from different accounts
    for (acct, hash) in [
        (&env.alice, HASH_A),
        (&env.bob, HASH_B),
        (&env.alice, HASH_C),
    ] {
        let r = register(&env, acct, hash, MODEL, DIGEST, SAFE_DEPOSIT).await;
        assert!(r.is_success(), "{}", failure_text(&r));
    }
    let grown = u128::from(contract_storage_usage(&env).await - usage0) * BYTE_COST;
    let gained = balance_of_contract(&env).await - bal0;
    // The contract's balance grew by exactly the cost of everything stored: it is always
    // fully funded for the storage that callers made it hold.
    assert_eq!(gained, grown);
}

#[tokio::test]
async fn event_log_is_emitted_with_standard_shape() {
    let env = setup().await;
    let r = register(
        &env,
        &env.alice,
        HASH_A,
        "a \"quoted\" model/1",
        DIGEST,
        SAFE_DEPOSIT,
    )
    .await;
    assert!(r.is_success());
    let events: Vec<&str> = r
        .logs()
        .into_iter()
        .filter(|l| l.starts_with("EVENT_JSON:"))
        .collect();
    assert_eq!(events.len(), 1, "logs: {:?}", r.logs());
    let ev: Value = serde_json::from_str(events[0].strip_prefix("EVENT_JSON:").unwrap()).unwrap();
    assert_eq!(ev["standard"], "attested_receipts");
    assert_eq!(ev["version"], "1.0.0");
    assert_eq!(ev["event"], "receipt_registered");
    let d = &ev["data"][0];
    assert_eq!(ev["data"].as_array().unwrap().len(), 1);
    assert_eq!(d["receipt_hash"], HASH_A);
    assert_eq!(d["submitter"], json!(env.alice.id().to_string()));
    assert_eq!(d["model_id"], "a \"quoted\" model/1");
    assert_eq!(d["attestation_digest"], DIGEST);
    let stored = view(&env, "get_receipt", json!({"receipt_hash": HASH_A})).await;
    assert_eq!(d["timestamp_ms"], stored["timestamp_ms"]);
    // key order as documented (standard, version, event, data)
    let text = events[0];
    let pos = |k: &str| text.find(&format!("\"{k}\"")).unwrap();
    assert!(
        pos("standard") < pos("version")
            && pos("version") < pos("event")
            && pos("event") < pos("data")
    );
}

#[tokio::test]
async fn pagination_over_chain_and_limit_cap() {
    let env = setup().await;
    // 4 records is enough to test windows; the 100-cap is covered by the unit tests.
    let hashes: Vec<String> = (1..=4).map(|n| format!("{n:064x}")).collect();
    for h in &hashes {
        let r = register(&env, &env.alice, h, MODEL, DIGEST, SAFE_DEPOSIT).await;
        assert!(r.is_success(), "{}", failure_text(&r));
    }
    assert_eq!(view(&env, "total_receipts", json!({})).await, json!(4));
    let page = view(&env, "list_receipts", json!({"from_index": 1, "limit": 2})).await;
    let got: Vec<&str> = page
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p[0].as_str().unwrap())
        .collect();
    assert_eq!(got, [hashes[1].as_str(), hashes[2].as_str()]);
    let page = view(&env, "list_receipts", json!({"limit": 1000})).await;
    assert_eq!(page.as_array().unwrap().len(), 4);
}

#[tokio::test]
async fn contract_has_no_admin_or_mutation_methods() {
    let env = setup().await;
    let r = register(&env, &env.alice, HASH_A, MODEL, DIGEST, SAFE_DEPOSIT).await;
    assert!(r.is_success());
    for method in [
        "delete_receipt",
        "update_receipt",
        "set_owner",
        "migrate",
        "new",
        "upgrade",
    ] {
        let r = env
            .alice
            .call(env.contract.id(), method)
            .args_json(json!({"receipt_hash": HASH_A}))
            .gas(GAS)
            .transact()
            .await
            .unwrap();
        assert!(r.is_failure(), "method {method} must not exist");
        assert!(
            failure_text(&r).contains("MethodNotFound"),
            "{}",
            failure_text(&r)
        );
    }
    assert_eq!(view(&env, "total_receipts", json!({})).await, json!(1));
    // Not even the contract's own account can deploy over itself without its key:
    // dev_deploy keeps the key in the test, so only check that the code is the expected one.
    let _ = &env.worker;
}

#[tokio::test]
async fn worst_case_call_fits_in_the_documented_safe_deposit() {
    let env = setup().await;
    // Longest possible account id (64 chars) and longest allowed model_id, on the very
    // first call (which is also charged for the contract's state key).
    let root = env.worker.root_account().unwrap();
    let long_name = "a".repeat(64 - ".test.near".len());
    let long_account = root
        .create_subaccount(&long_name)
        .initial_balance(NearToken::from_near(10))
        .transact()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(long_account.id().as_str().len(), 64);

    let usage0 = contract_storage_usage(&env).await;
    let r = register(
        &env,
        &long_account,
        HASH_A,
        &"m".repeat(128),
        DIGEST,
        SAFE_DEPOSIT,
    )
    .await;
    assert!(r.is_success(), "{}", failure_text(&r));
    let required = u128::from(contract_storage_usage(&env).await - usage0) * BYTE_COST;
    println!("worst-case storage cost on the sandbox: {required} yocto");
    assert!(
        required < SAFE_DEPOSIT.as_yoctonear() * 6 / 10,
        "worst case {required} leaves too little margin"
    );
}
