use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_tungstenite::{connect_async, tungstenite::Message};

use crate::error::{Result, SdkError};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum WsIncomingMessage {
    #[serde(rename = "message_received")]
    MessageReceived(IncomingMessage),
    #[serde(rename = "typing_started")]
    TypingStarted(TypingEvent),
    #[serde(rename = "typing_stopped")]
    TypingStopped(TypingEvent),
    #[serde(rename = "presence_updated")]
    PresenceUpdated(PresenceEvent),
    #[serde(rename = "user_went_offline")]
    UserWentOffline(PresenceEvent),
    #[serde(rename = "friend_request_received")]
    FriendRequestReceived(FriendRequestEvent),
    #[serde(rename = "friend_request_accepted")]
    FriendRequestAccepted(FriendRequestEvent),
    #[serde(rename = "incoming_call")]
    IncomingCall(CallEvent),
    #[serde(rename = "key_exchange_pending")]
    KeyExchangePending(KeyExchangeEvent),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomingMessage {
    pub id: String,
    pub conversation_id: String,
    pub sender_id: String,
    pub encrypted_content: Vec<u8>,
    pub signature: Vec<u8>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypingEvent {
    pub conversation_id: String,
    pub user_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceEvent {
    pub user_id: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriendRequestEvent {
    pub from_user_id: String,
    pub to_user_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallEvent {
    pub call_id: String,
    pub caller_id: String,
    pub callee_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyExchangeEvent {
    pub exchange_id: String,
    pub from_user_id: String,
    pub conversation_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum WsOutgoingMessage {
    #[serde(rename = "typing")]
    Typing(TypingOutgoing),
    #[serde(rename = "update_presence")]
    UpdatePresence(PresenceOutgoing),
    #[serde(rename = "subscribe_conversation")]
    SubscribeConversation(SubscribeConversation),
    #[serde(rename = "subscribe_user")]
    SubscribeUser(SubscribeUser),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypingOutgoing {
    pub conversation_id: String,
    pub is_typing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceOutgoing {
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeConversation {
    pub conversation_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeUser {
    pub user_id: String,
}

pub struct WebSocketClient {
    sender: mpsc::Sender<WsOutgoingMessage>,
    receiver: mpsc::Receiver<WsIncomingMessage>,
}

impl WebSocketClient {
    pub async fn connect(ws_url: &str, auth_token: &str) -> Result<Self> {
        let url = format!("{}?token={}", ws_url, auth_token);

        let (ws_stream, _) = connect_async(&url)
            .await
            .map_err(|e| SdkError::Encryption(format!("WebSocket connection failed: {}", e)))?;

        let (mut write, mut read) = ws_stream.split();

        let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<WsOutgoingMessage>(100);
        let (incoming_tx, incoming_rx) = mpsc::channel::<WsIncomingMessage>(100);

        tokio::spawn(async move {
            while let Some(msg) = outgoing_rx.recv().await {
                let json = serde_json::to_string(&msg).unwrap();
                if write.send(Message::Text(json)).await.is_err() {
                    break;
                }
            }
        });

        tokio::spawn(async move {
            while let Some(msg) = read.next().await {
                if let Ok(Message::Text(text)) = msg {
                    if let Ok(incoming) = serde_json::from_str::<WsIncomingMessage>(&text) {
                        if incoming_tx.send(incoming).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        Ok(Self {
            sender: outgoing_tx,
            receiver: incoming_rx,
        })
    }

    pub async fn send(&self, message: WsOutgoingMessage) -> Result<()> {
        self.sender
            .send(message)
            .await
            .map_err(|e| SdkError::Encryption(format!("Failed to send message: {}", e)))
    }

    pub async fn recv(&mut self) -> Option<WsIncomingMessage> {
        self.receiver.recv().await
    }

    pub async fn send_typing(&self, conversation_id: &str, is_typing: bool) -> Result<()> {
        self.send(WsOutgoingMessage::Typing(TypingOutgoing {
            conversation_id: conversation_id.to_string(),
            is_typing,
        }))
        .await
    }

    pub async fn update_presence(&self, status: &str) -> Result<()> {
        self.send(WsOutgoingMessage::UpdatePresence(PresenceOutgoing {
            status: status.to_string(),
        }))
        .await
    }

    pub async fn subscribe_conversation(&self, conversation_id: &str) -> Result<()> {
        self.send(WsOutgoingMessage::SubscribeConversation(
            SubscribeConversation {
                conversation_id: conversation_id.to_string(),
            },
        ))
        .await
    }

    pub async fn subscribe_user(&self, user_id: &str) -> Result<()> {
        self.send(WsOutgoingMessage::SubscribeUser(SubscribeUser {
            user_id: user_id.to_string(),
        }))
        .await
    }
}
