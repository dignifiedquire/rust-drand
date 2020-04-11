mod curve;
mod orchestrator;

pub mod board;
pub mod node;

pub type Group = threshold::dkg::Group<self::curve::KeyCurve>;
pub type DkgNode = threshold::dkg::Node<self::curve::KeyCurve>;
pub use self::board::{Board, ProtocolMessage};
pub use self::node::Node;
pub use threshold::Index;
