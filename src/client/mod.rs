#[cfg(feature = "client")]
pub mod api;

#[cfg(feature = "client")]
pub mod websocket;

#[cfg(feature = "client")]
pub use api::ApiClient;

#[cfg(feature = "client")]
pub use websocket::WebSocketClient;
