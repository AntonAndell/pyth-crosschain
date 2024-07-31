pub mod error;
pub mod testing;

pub use pyth_sdk::{Price, PriceFeed, PriceIdentifier, UnixTimestamp};
use {
    cosmwasm_schema::{cw_serde, QueryResponses},
    cosmwasm_std::{
        to_binary, Addr, Binary, Coin, QuerierWrapper, QueryRequest, StdResult, WasmQuery,
    },
    std::time::Duration,
};

#[derive(Eq)]
#[cw_serde]
pub enum ExecuteMsg {
    UpdatePriceFeeds { data: Vec<Binary> },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(PriceFeedResponse)]
    PriceFeed { id: PriceIdentifier },
    #[returns(Duration)]
    GetValidTimePeriod,
}

#[cw_serde]
pub struct PriceFeedResponse {
    pub price_feed: PriceFeed,
}

/// Queries the price on-chain
pub fn query_price_feed(
    querier: &QuerierWrapper,
    contract_addr: Addr,
    id: PriceIdentifier,
) -> StdResult<PriceFeedResponse> {
    let price_feed_response = querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr: contract_addr.into_string(),
        msg: to_binary(&QueryMsg::PriceFeed { id })?,
    }))?;
    Ok(price_feed_response)
}

/// Get the default length of time for which a price update remains valid.
pub fn get_valid_time_period(querier: &QuerierWrapper, contract_addr: Addr) -> StdResult<Duration> {
    querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr: contract_addr.into_string(),
        msg: to_binary(&QueryMsg::GetValidTimePeriod)?,
    }))
}
