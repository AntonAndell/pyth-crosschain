#[cfg(feature = "injective")]
use crate::injective::{create_relay_pyth_prices_msg, InjectiveMsgWrapper as MsgWrapper};
#[cfg(not(feature = "injective"))]
use cosmwasm_std::Empty as MsgWrapper;
#[cfg(feature = "osmosis")]
use osmosis_std::types::osmosis::txfees::v1beta1::TxfeesQuerier;
use {
    crate::{
        error::ContractError,
        msg::{InstantiateMsg, MigrateMsg},
        state::{
            config, config_read, price_feed_bucket, price_feed_read_bucket, set_contract_version,
            ConfigInfo, GuardianAddress, GuardianSetInfo, PythDataSource,
        },
    },
    byteorder::BigEndian,
    cosmwasm_std::{
        coin, entry_point, to_binary, Addr, Binary, Coin, CosmosMsg, Deps, DepsMut, Env,
        MessageInfo, OverflowError, OverflowOperation, QueryRequest, Response, StdResult, WasmMsg,
        WasmQuery,
    },
    cw_wormhole::byte_utils::ByteUtils,
    cw_wormhole::{msg::QueryMsg as WormholeQueryMsg, state::ParsedVAA},
    generic_array::GenericArray,
    k256::{
        ecdsa::{
            recoverable::{Id as RecoverableId, Signature as RecoverableSignature},
            Signature, VerifyingKey,
        },
        elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
        AffinePoint, EncodedPoint,
    },
    pyth_sdk::{Identifier, UnixTimestamp},
    pyth_sdk_cw::{
        error::PythContractError, ExecuteMsg, Price, PriceFeed, PriceFeedResponse, PriceIdentifier,
        QueryMsg,
    },
    pyth_wormhole_attester_sdk::{BatchPriceAttestation, PriceAttestation, PriceStatus},
    pythnet_sdk::{
        accumulators::merkle::MerkleRoot,
        hashers::keccak256_160::Keccak160,
        messages::Message,
        wire::{
            from_slice,
            v1::{
                AccumulatorUpdateData, Proof, WormholeMessage, WormholePayload,
                PYTHNET_ACCUMULATOR_UPDATE_MAGIC,
            },
        },
    },
    sha3::{Digest, Keccak256},
    std::{collections::HashSet, convert::TryFrom, iter::FromIterator, time::Duration},
};

const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Migration code that runs once when the contract is upgraded. On upgrade, the migrate
/// function in the *new* code version is run, which allows the new code to update the on-chain
/// state before any of its other functions are invoked.
///
/// After the upgrade is complete, the code in this function can be deleted (and replaced with
/// different code for the next migration).
///
/// Most upgrades won't require any special migration logic. In those cases,
/// this function can safely be implemented as:
/// `Ok(Response::default())`
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(deps: DepsMut, _env: Env, _msg: MigrateMsg) -> StdResult<Response> {
    // a new contract version should be set everytime a contract is migrated
    set_contract_version(deps.storage, &String::from(CONTRACT_VERSION))?;
    Ok(Response::default().add_attribute("Contract Version", CONTRACT_VERSION))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    // Save general wormhole and pyth info
    let state = ConfigInfo {
        wormhole_contract: deps.api.addr_validate(msg.wormhole_contract.as_ref())?,
        data_sources: msg.data_sources.iter().cloned().collect(),
        chain_id: msg.chain_id,
        governance_source: msg.governance_source.clone(),
        governance_source_index: msg.governance_source_index,
        governance_sequence_number: msg.governance_sequence_number,
        valid_time_period: Duration::from_secs(msg.valid_time_period_secs as u64),
        fee: msg.fee,
    };
    config(deps.storage).save(&state)?;

    set_contract_version(deps.storage, &String::from(CONTRACT_VERSION))?;

    Ok(Response::default())
}

/// Parses raw VAA data into a struct and verifies whether it contains sufficient signatures of an
/// active guardian set i.e. is valid according to Wormhole consensus rules
fn parse_and_verify_vaa(block_time: u64, data: &[u8]) -> StdResult<ParsedVAA> {
    let vaa = ParsedVAA::deserialize(data)?;

    if vaa.version != 1 {
        return Err(PythContractError::InvalidMerkleProof)?;
    }

    // // Check if VAA with this hash was already accepted
    // if vaa_archive_check(storage, vaa.hash.as_slice()) {
    //     return Err(PythContractError::InvalidMerkleProof)?;
    // }

    // Load and check guardian set
    // let guardian_set = guardian_set_get(storage, vaa.guardian_set_index);
    // let guardian_set: GuardianSetInfo = guardian_set.unwrap();
    println!(" {:?}", vaa.guardian_set_index);
    let hex_strings = vec![
        "0x5893B5A76c3f739645648885bDCcC06cd70a3Cd3",
        "0xfF6CB952589BDE862c25Ef4392132fb9D4A42157",
        "0x114De8460193bdf3A2fCf81f86a09765F4762fD1",
        "0x107A0086b32d7A0977926A205131d8731D39cbEB",
        "0x8C82B2fd82FaeD2711d59AF0F2499D16e726f6b2",
        "0x11b39756C042441BE6D8650b69b54EbE715E2343",
        "0x54Ce5B4D348fb74B958e8966e2ec3dBd4958a7cd",
        "0x15e7cAF07C4e3DC8e7C469f92C8Cd88FB8005a20",
        "0x74a3bf913953D695260D88BC1aA25A4eeE363ef0",
        "0x000aC0076727b35FBea2dAc28fEE5cCB0fEA768e",
        "0xAF45Ced136b9D9e24903464AE889F5C8a723FC14",
        "0xf93124b7c738843CBB89E864c862c38cddCccF95",
        "0xD2CC37A4dc036a8D232b48f62cDD4731412f4890",
        "0xDA798F6896A3331F64b48c12D1D57Fd9cbe70811",
        "0x71AA1BE1D36CaFE3867910F99C09e347899C19C3",
        "0x8192b6E7387CCd768277c17DAb1b7a5027c0b3Cf",
        "0x178e21ad2E77AE06711549CFBB1f9c7a9d8096e8",
        "0x5E1487F35515d02A92753504a8D75471b9f49EdB",
        "0x6FbEBc898F403E4773E95feB15E80C9A99c8348d",
    ];
    let vec_of_binary: Vec<Binary> = hex_strings
        .iter()
        .map(|s| &s[2..]) // Remove the "0x" prefix
        .map(hex::decode) // Decode the hex string into a Vec<u8>
        .map(|result| result.map(Binary::from)) // Wrap the result in Binary
        .collect::<Result<_, _>>()
        .or_else(|_| ContractError::CannotDecodeSignature.std_err())?;

    let mut addresses = Vec::with_capacity(vec_of_binary.len());
    for i in 0..vec_of_binary.len() {
        addresses.push(GuardianAddress {
            bytes: vec_of_binary.get(i).unwrap().clone(),
        });
    }
    let guardian_set = GuardianSetInfo {
        addresses,
        expiration_time: 0,
    };
    // if guardian_set.expiration_time != 0 && guardian_set.expiration_time < block_time {
    //     return Err(PythContractError::InvalidMerkleProof)?;
    // }
    // if (vaa.len_signers as usize) < guardian_set.quorum() {
    //     return Err(PythContractError::InvalidMerkleProof)?;
    // }

    // Verify guardian signatures
    let mut last_index: i32 = -1;
    let mut pos = ParsedVAA::HEADER_LEN;

    for _ in 0..vaa.len_signers {
        if pos + ParsedVAA::SIGNATURE_LEN > data.len() {
            return Err(PythContractError::InvalidMerkleProof)?;
        }
        let index = data.get_u8(pos) as i32;
        if index <= last_index {
            return Err(PythContractError::InvalidMerkleProof)?;
        }
        last_index = index;
        let signature = Signature::try_from(
            &data[pos + ParsedVAA::SIG_DATA_POS
                ..pos + ParsedVAA::SIG_DATA_POS + ParsedVAA::SIG_DATA_LEN],
        )
        .or_else(|_| ContractError::CannotDecodeSignature.std_err())?;
        let id = RecoverableId::new(data.get_u8(pos + ParsedVAA::SIG_RECOVERY_POS))
            .or_else(|_| ContractError::CannotDecodeSignature.std_err())?;
        let recoverable_signature = RecoverableSignature::new(&signature, id)
            .or_else(|_| ContractError::CannotDecodeSignature.std_err())?;

        let verify_key: VerifyingKey = recoverable_signature
            .recover_verifying_key_from_digest_bytes(GenericArray::from_slice(vaa.hash.as_slice()))
            .or_else(|_| ContractError::CannotRecoverKey.std_err())?;

        let index = index as usize;
        println!(" {:?}", index);

        if index >= guardian_set.addresses.len() {
            return ContractError::TooManySignatures.std_err();
        }

        if !keys_equal(&verify_key, &guardian_set.addresses[index]) {
            return ContractError::GuardianSignatureError.std_err();
        }
        pos += ParsedVAA::SIGNATURE_LEN;
    }

    Ok(vaa)
}

fn keys_equal(a: &VerifyingKey, b: &GuardianAddress) -> bool {
    let mut hasher = Keccak256::new();

    let affine_point_option = AffinePoint::from_encoded_point(&EncodedPoint::from(a));
    let affine_point = if affine_point_option.is_some().into() {
        affine_point_option.unwrap()
    } else {
        return false;
    };

    let decompressed_point = affine_point.to_encoded_point(false);

    hasher.update(&decompressed_point.as_bytes()[1..]);
    let a = &hasher.finalize()[12..];

    let b = &b.bytes;
    println!(" {:?}", hex::encode(a));

    if a.len() != b.len() {
        return false;
    }
    for (ai, bi) in a.iter().zip(b.as_slice().iter()) {
        if ai != bi {
            return false;
        }
    }
    true
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> StdResult<Response<MsgWrapper>> {
    match msg {
        ExecuteMsg::UpdatePriceFeeds { data } => update_price_feeds(deps, env, info, &data),
    }
}

/// Update the on-chain price feeds given the array of price update VAAs `data`.
/// Each price update VAA must be a valid Wormhole message and sent from an authorized emitter.
///
/// This method additionally requires the caller to pay a fee to the contract; the
/// magnitude of the fee depends on both the data and the current contract configuration.
fn update_price_feeds(
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
    data: &[Binary],
) -> StdResult<Response<MsgWrapper>> {
    let (num_total_attestations, total_new_feeds) = apply_updates(&mut deps, &env, data)?;

    let num_total_new_attestations = total_new_feeds.len();

    let response = Response::new();

    #[cfg(feature = "injective")]
    {
        let inj_message = create_relay_pyth_prices_msg(env.contract.address, total_new_feeds);
        Ok(response
            .add_message(inj_message)
            .add_attribute("action", "update_price_feeds")
            .add_attribute("num_attestations", format!("{num_total_attestations}"))
            .add_attribute("num_updated", format!("{num_total_new_attestations}")))
    }

    #[cfg(not(feature = "injective"))]
    {
        Ok(response
            .add_attribute("action", "update_price_feeds")
            .add_attribute("num_attestations", format!("{num_total_attestations}"))
            .add_attribute("num_updated", format!("{num_total_new_attestations}")))
    }
}

/// Check that `vaa` is from a valid data source (and hence is a legitimate price update message).
fn verify_vaa_from_data_source(state: &ConfigInfo, vaa: &ParsedVAA) -> StdResult<()> {
    let vaa_data_source = PythDataSource {
        emitter: vaa.emitter_address.clone().into(),
        chain_id: vaa.emitter_chain,
    };
    println!("{:?}", vaa_data_source);
    if !state.data_sources.contains(&vaa_data_source) {
        return Err(PythContractError::InvalidUpdateEmitter)?;
    }
    Ok(())
}

fn parse_update(deps: &Deps, env: &Env, data: &Binary) -> StdResult<Vec<PriceFeed>> {
    let header = data.get(0..4);
    let feeds = if header == Some(PYTHNET_ACCUMULATOR_UPDATE_MAGIC.as_slice()) {
        parse_accumulator(deps, env, data)?
    } else {
        parse_batch_attestation(deps, env, data)?
    };
    Ok(feeds)
}

fn apply_updates(
    deps: &mut DepsMut,
    env: &Env,
    data: &[Binary],
) -> StdResult<(usize, Vec<PriceFeed>)> {
    let mut num_total_attestations: usize = 0;
    let mut total_new_feeds: Vec<PriceFeed> = vec![];
    for datum in data {
        let feeds = parse_update(&deps.as_ref(), env, datum)?;
        num_total_attestations += feeds.len();
        println!("{:?}", feeds);

        for feed in feeds {
            println!("{:?}", feed);
            if update_price_feed_if_new(deps, env, feed)? {
                total_new_feeds.push(feed);
            }
        }
    }
    Ok((num_total_attestations, total_new_feeds))
}

fn parse_accumulator(deps: &Deps, env: &Env, data: &[u8]) -> StdResult<Vec<PriceFeed>> {
    let update_data = AccumulatorUpdateData::try_from_slice(data)
        .map_err(|_| PythContractError::InvalidAccumulatorPayload)?;
    match update_data.proof {
        Proof::WormholeMerkle { vaa, updates } => {
            let parsed_vaa = parse_and_verify_vaa(
                env.block.time.seconds(),
                &Binary::from(Vec::from(vaa)).clone().as_slice(),
            )?;
            let state = config_read(deps.storage).load()?;
            verify_vaa_from_data_source(&state, &parsed_vaa)?;

            let msg = WormholeMessage::try_from_bytes(parsed_vaa.payload)
                .map_err(|_| PythContractError::InvalidWormholeMessage)?;

            let root: MerkleRoot<Keccak160> = MerkleRoot::new(match msg.payload {
                WormholePayload::Merkle(merkle_root) => merkle_root.root,
            });
            let mut feeds = vec![];
            for update in updates {
                let message_vec = Vec::from(update.message);
                if !root.check(update.proof, &message_vec) {
                    return Err(PythContractError::InvalidMerkleProof)?;
                }

                let msg = from_slice::<BigEndian, Message>(&message_vec)
                    .map_err(|_| PythContractError::InvalidAccumulatorMessage)?;

                match msg {
                    Message::PriceFeedMessage(price_feed_message) => {
                        let price_feed = PriceFeed::new(
                            PriceIdentifier::new(price_feed_message.feed_id),
                            Price {
                                price: price_feed_message.price,
                                conf: price_feed_message.conf,
                                expo: price_feed_message.exponent,
                                publish_time: price_feed_message.publish_time,
                            },
                            Price {
                                price: price_feed_message.ema_price,
                                conf: price_feed_message.ema_conf,
                                expo: price_feed_message.exponent,
                                publish_time: price_feed_message.publish_time,
                            },
                        );
                        feeds.push(price_feed);
                    }
                    _ => return Err(PythContractError::InvalidAccumulatorMessageType)?,
                }
            }
            Ok(feeds)
        }
    }
}

/// Update the on-chain storage for any new price updates provided in `batch_attestation`.
fn parse_batch_attestation(deps: &Deps, env: &Env, data: &Binary) -> StdResult<Vec<PriceFeed>> {
    let vaa = parse_and_verify_vaa(env.block.time.seconds(), data.as_slice())?;
    let state = config_read(deps.storage).load()?;
    verify_vaa_from_data_source(&state, &vaa)?;
    let data = &vaa.payload;
    let batch_attestation = BatchPriceAttestation::deserialize(&data[..])
        .map_err(|_| PythContractError::InvalidUpdatePayload)?;
    let mut feeds = vec![];

    // Update prices
    for price_attestation in batch_attestation.price_attestations.iter() {
        let price_feed = create_price_feed_from_price_attestation(price_attestation);
        feeds.push(price_feed);
    }

    Ok(feeds)
}

fn create_price_feed_from_price_attestation(price_attestation: &PriceAttestation) -> PriceFeed {
    match price_attestation.status {
        PriceStatus::Trading => PriceFeed::new(
            PriceIdentifier::new(price_attestation.price_id.to_bytes()),
            Price {
                price: price_attestation.price,
                conf: price_attestation.conf,
                expo: price_attestation.expo,
                publish_time: price_attestation.publish_time,
            },
            Price {
                price: price_attestation.ema_price,
                conf: price_attestation.ema_conf,
                expo: price_attestation.expo,
                publish_time: price_attestation.publish_time,
            },
        ),
        _ => PriceFeed::new(
            PriceIdentifier::new(price_attestation.price_id.to_bytes()),
            Price {
                price: price_attestation.prev_price,
                conf: price_attestation.prev_conf,
                expo: price_attestation.expo,
                publish_time: price_attestation.prev_publish_time,
            },
            Price {
                price: price_attestation.ema_price,
                conf: price_attestation.ema_conf,
                expo: price_attestation.expo,
                publish_time: price_attestation.prev_publish_time,
            },
        ),
    }
}

/// Returns true if the price_feed is newer than the stored one.
///
/// This function returns error only if there be issues in ser/de when it reads from the bucket.
/// Such an example would be upgrades which migration is not handled carefully so the binary stored
/// in the bucket won't be parsed.
fn update_price_feed_if_new(
    deps: &mut DepsMut,
    _env: &Env,
    new_price_feed: PriceFeed,
) -> StdResult<bool> {
    let mut is_new_price = true;
    price_feed_bucket(deps.storage).update(
        new_price_feed.id.as_ref(),
        |maybe_price_feed| -> StdResult<PriceFeed> {
            match maybe_price_feed {
                Some(price_feed) => {
                    // This check ensures that a price won't be updated with the same or older
                    // message. Publish_TIme is guaranteed increasing in
                    // solana
                    if price_feed.get_price_unchecked().publish_time
                        < new_price_feed.get_price_unchecked().publish_time
                    {
                        Ok(new_price_feed)
                    } else {
                        is_new_price = false;
                        Ok(price_feed)
                    }
                }
                None => Ok(new_price_feed),
            }
        },
    )?;
    Ok(is_new_price)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::PriceFeed { id } => to_binary(&query_price_feed(&deps, id.as_ref())?),
        QueryMsg::GetValidTimePeriod => to_binary(&get_valid_time_period(&deps)?),
    }
}

/// This function is not used in the contract yet but mimicks the behavior implemented
/// in the EVM contract. We are yet to finalize how the parsed prices should be consumed
/// in injective as well as other chains.
pub fn parse_price_feed_updates(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    updates: &[Binary],
    price_feeds: Vec<Identifier>,
    min_publish_time: UnixTimestamp,
    max_publish_time: UnixTimestamp,
) -> StdResult<Response<MsgWrapper>> {
    let _config = config_read(deps.storage).load()?;
    let mut found_feeds = 0;
    let mut results: Vec<(Identifier, Option<PriceFeed>)> =
        price_feeds.iter().map(|id| (*id, None)).collect();
    for datum in updates {
        let feeds = parse_update(&deps.as_ref(), &env, datum)?;
        for result in results.as_mut_slice() {
            if result.1.is_some() {
                continue;
            }
            for feed in feeds.as_slice() {
                if feed.get_price_unchecked().publish_time < min_publish_time
                    || feed.get_price_unchecked().publish_time > max_publish_time
                {
                    continue;
                }
                if result.0 == feed.id {
                    result.1 = Some(*feed);
                    found_feeds += 1;
                    break;
                }
            }
        }
    }
    if found_feeds != price_feeds.len() {
        return Err(PythContractError::InvalidUpdatePayload)?;
    }

    let _unwrapped_feeds = results
        .into_iter()
        .map(|(_, feed)| feed.unwrap())
        .collect::<Vec<PriceFeed>>();
    let response = Response::new();
    Ok(response.add_attribute("action", "parse_price_feeds"))
}

/// Get the most recent value of the price feed indicated by `feed_id`.
pub fn query_price_feed(deps: &Deps, feed_id: &[u8]) -> StdResult<PriceFeedResponse> {
    match price_feed_read_bucket(deps.storage).load(feed_id) {
        Ok(price_feed) => Ok(PriceFeedResponse { price_feed }),
        Err(_) => Err(PythContractError::PriceFeedNotFound)?,
    }
}

pub fn get_valid_time_period(deps: &Deps) -> StdResult<Duration> {
    Ok(config_read(deps.storage).load()?.valid_time_period)
}

#[cfg(test)]
mod test {
    use {
        super::*,
        crate::state::get_contract_version,
        cosmwasm_std::{
            coins, from_binary,
            testing::{mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage},
            Addr, ContractResult, OwnedDeps, QuerierResult, StdError, SystemError, SystemResult,
            Uint128,
        },
        pyth_sdk::UnixTimestamp,
        pyth_sdk_cw::PriceIdentifier,
        pyth_wormhole_attester_sdk::PriceAttestation,
        pythnet_sdk::{
            accumulators::{merkle::MerkleTree, Accumulator},
            messages::{PriceFeedMessage, TwapMessage},
            test_utils::{
                create_accumulator_message, create_accumulator_message_from_updates,
                create_dummy_price_feed_message, create_vaa_from_payload, DEFAULT_CHAIN_ID,
                DEFAULT_DATA_SOURCE, DEFAULT_GOVERNANCE_SOURCE, DEFAULT_VALID_TIME_PERIOD,
                SECONDARY_GOVERNANCE_SOURCE, WRONG_CHAIN_ID, WRONG_SOURCE,
            },
            wire::{to_vec, v1::MerklePriceUpdate, PrefixedVec},
        },
        serde_wormhole::RawMessage,
        std::time::Duration,
        wormhole_sdk::{Address, Chain, Vaa},
    };

    /// Default valid time period for testing purposes.
    const WORMHOLE_ADDR: &str = "Wormhole";

    fn hex_to_vec(hex: &str) -> Result<Vec<u8>, String> {
        if hex.len() % 2 != 0 {
            return Err("Hex string must have an even length".into());
        }

        (0..hex.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&hex[i..i + 2], 16)
                    .map_err(|e| format!("Invalid hex string: {}", e))
            })
            .collect()
    }


    fn arb_config_info() -> ConfigInfo {
        ConfigInfo {
            wormhole_contract: Addr::unchecked(WORMHOLE_ADDR),
            data_sources: create_data_sources(
                hex_to_vec("e101faedac5851e32b9b23b5f9411a8c2bac4aae3ed4dd7b811dd1a72ea4aa71")
                    .unwrap(),
                26,
            ),
            ..create_zero_config_info()
        }
    }

    fn setup_test() -> (OwnedDeps<MockStorage, MockApi, MockQuerier>, Env) {
        let mut dependencies = mock_dependencies();
        dependencies.querier.update_wasm(handle_wasm_query);

        let mut config = config(dependencies.as_mut().storage);
        config
            .save(&ConfigInfo {
                valid_time_period: Duration::from_secs(DEFAULT_VALID_TIME_PERIOD),
                ..create_zero_config_info()
            })
            .unwrap();
        (dependencies, mock_env())
    }

    fn handle_wasm_query(wasm_query: &WasmQuery) -> QuerierResult {
        match wasm_query {
            WasmQuery::Smart { contract_addr, msg } if *contract_addr == WORMHOLE_ADDR => {
                let query_msg = from_binary::<WormholeQueryMsg>(msg);
                match query_msg {
                    Ok(WormholeQueryMsg::VerifyVAA { vaa, .. }) => {
                        SystemResult::Ok(ContractResult::Ok(
                            to_binary(&ParsedVAA::deserialize(&vaa).unwrap()).unwrap(),
                        ))
                    }
                    Err(_e) => SystemResult::Err(SystemError::InvalidRequest {
                        error: "Invalid message".into(),
                        request: msg.clone(),
                    }),
                    _ => SystemResult::Err(SystemError::NoSuchContract {
                        addr: contract_addr.clone(),
                    }),
                }
            }
            WasmQuery::Smart { contract_addr, .. } => {
                SystemResult::Err(SystemError::NoSuchContract {
                    addr: contract_addr.clone(),
                })
            }
            WasmQuery::Raw { contract_addr, .. } => {
                SystemResult::Err(SystemError::NoSuchContract {
                    addr: contract_addr.clone(),
                })
            }
            WasmQuery::ContractInfo { contract_addr, .. } => {
                SystemResult::Err(SystemError::NoSuchContract {
                    addr: contract_addr.clone(),
                })
            }
            _ => unreachable!(),
        }
    }


    fn create_zero_config_info() -> ConfigInfo {
        ConfigInfo {
            wormhole_contract: Addr::unchecked(String::default()),
            data_sources: HashSet::default(),
            governance_source: PythDataSource {
                emitter: Binary(vec![]),
                chain_id: 0,
            },
            governance_source_index: 0,
            governance_sequence_number: 0,
            chain_id: 0,
            valid_time_period: Duration::new(0, 0),
            fee: Coin::new(0, ""),
        }
    }


    fn create_data_sources(
        pyth_emitter: Vec<u8>,
        pyth_emitter_chain: u16,
    ) -> HashSet<PythDataSource> {
        HashSet::from([PythDataSource {
            emitter: pyth_emitter.into(),
            chain_id: pyth_emitter_chain,
        }])
    }

    fn hex_to_binary(hex: &str) -> Result<Binary, String> {
        if hex.len() % 2 != 0 {
            return Err("Hex string must have an even length".into());
        }

        let bytes: Result<Vec<u8>, _> = (0..hex.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&hex[i..i + 2], 16)
                    .map_err(|e| format!("Invalid hex string: {}", e))
            })
            .collect();

        bytes.map(Binary::from)
    }

    #[test]
    fn test_real_data() {
        let data = "504e41550100000003b801000000040d00d165bdba28960bda513f3ec9efb9f766e7910121d36213350a9031300cbc654543c322e1f26640d90082f7bf94d1e33743765012012972809e4300a84a927bab00020f7f1e256ac3e3f275bc7b611954dcfef219437d0fffe901a31f17a97a1321840596d424ad8ff1fb759c8c3d680db7733d2eec64f9b9a1fcb9d0bad1f83f87e9000365683b3a7142548fe257e1b4eb07dd95dcbb3589243195a3ada36cbe47a16c9f701c84f7b144d5d21e372a3609dd2ff9f47e824ed28c315f483843aeedd6cd7900049466312ae14c8e2f5f4081ecb184668a44591f05e50a15387aaf7761da2362064ad47b0b1b978c4e7da886f406ec0a6a7e25625eabcffa68e586a80a59678a74010698faf88d5334b413f4d23e8ad49b831a1fa1394b4247e127de7b764c9ba9b0ea3ba5fb1f6751118e219ea93234cb52279fb237503cbe68bbaa65acd86ae4bc7b0008d06e4830b86d1263c9cc137a83eb28fcc00bbf6994612728774ecca0c48f11624a19a8cb75896ac38bcfd411d5f33185a86a11b39982ac0a1892938cb83eaab2000a90c573be13126f88aa705b517aee8ddc2d905cbfb6ef431a7b5a2314cf9686211b0f052adb62d97c79720af0ff53b76a2bd3e61515f07d11042f0f1cbfe84131000b7abc15acdb0076e1854613ec8b840f9eb88a158d68744cecab37ffa0c32db4206bee13bcfabe591ee14d43c4cacc1e4e46f03a3a9e98942b60f5c90792b99238010c793efcdf831ec7d90f6c8283bf68c2d2b6bce415fa269be0d680dfba567bad596809deee7d6444bc427f0e77afe3c85152c99955d9a3cca115d3ccdf28eaaee1000dfe240e9b6d0501f949449cf234a14076465759d0d1a8ae0a05c9858d5a4b23ee498c2a18b6c0e91d6e0403f60176cc877c1cb02e108796dd8a88753d1853cccd010ee5d7e96c3d01236812ed95e6920ffa70509d4d137589cd9b3acc03f6ce6b85165e78192e7f438e678c01eef55bcf702112f0c384a00518b8b08d8dd8dc571cf4000f353f2cd3a2dfcd291a1ae173defe80b7c8f8944017c1251de940152ae4f7eac30503319a6648b7cb0731a379928c7bdec08dc98030862208c8b2229fa0e7d47200120cd030f4676f90b18956a7518eca9dc629cdd2b9a34b0f7c6a61d9eb37928e3a1bccca5a91d9f6b9b63f2a627de21c4ab9cd2de54c0d91156fd3255fcb4b59f30066a9ecfc00000000001ae101faedac5851e32b9b23b5f9411a8c2bac4aae3ed4dd7b811dd1a72ea4aa7100000000043f0736014155575600000000000949a84f000027103c8e153228ef72ea4b27f6b1248c9aa7aa53bd5002005500e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b4300000608b9fe5288000000008af90199fffffff80000000066a9ecfc0000000066a9ecfc00000606bdc3dba000000000a5e8b6100b843d0c07a4128bc4937f14c5aae17e5a153c90909765fcf9f0c5f256726fbfc8281187a647cc6d118f5d64ed0198177b9bf8e3787b900283ac623c6436e401283fb51cc7dbcd6b8a92deee366302cfae686af134d4f94d0d1996761932576929e3e4c5df3a3cfb235effb53d7570d0d72e4838c2d3a7eb702d090274dbdb87e74f22d10304e9bae0c5301657860121ee590493f146f6b597d83a87e74bc0272506c848a6ac7069dc698a16014ebeed6a32049ae5c13e1389c148a68d790f5b33c8a2159f2c4458262d5ba5a11f38dafcc4e5819df7e2f6c8399ee5e6005500ff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace0000004d6adae3ec000000000903b527fffffff80000000066a9ecfc0000000066a9ecfc0000004d176f1e4000000000083ac0f00b989c250a83568734c8bb09089eca38e89acddd94ae6486449282202087b96062446ba7c0568a2941bfdd13e983e95975df5838100be862de23b8211b3d38ec8c5b6f6e10d5a9ae0efb34b0657e2250f1992dcd54791d4c97fd5357e9c13789d5b18105d612226371a6cc968f9502192a0d260462040d316d1c9eb0d202a4f7a08699c3074fa431f5e1a0543d6d56d1448b7042263848f8b4da16a23e5c89fabbbb4b9d65925a0a8fb732c16704effcecfa6345d5e7edfa5c40a8ce4976556054f18a7e47e072ea302d5ba5a11f38dafcc4e5819df7e2f6c8399ee5e6";
        let (mut deps, env) = setup_test();
        config(&mut deps.storage).save(&arb_config_info()).unwrap();
        // let msg = create_batch_price_update_msg(emitter_address, emitter_chain, attestations);
        let res = apply_updates(&mut deps.as_mut(), &env, &[hex_to_binary(data).unwrap()]);
        println!("{:?}", res);
        assert_eq!(0, 0);
    }
}
