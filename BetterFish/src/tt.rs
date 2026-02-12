use shakmaty::Move;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    Exact,
    LowerBound,
    UpperBound,
}

#[derive(Clone)]
pub struct TTEntry {
    pub depth: u32,
    pub score: i32,
    pub node_type: NodeType,
    pub best_move: Option<Move>,
}
