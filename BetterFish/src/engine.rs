use shakmaty::{Chess, Move, Position, MoveList, Role, Color};
use shakmaty::zobrist::{ZobristHash, Zobrist64};
use crate::evaluation::evaluate;
use crate::tt::{TTEntry, NodeType};
use crate::constants::get_material_value;
use crate::opening_book::OpeningBook;
use std::collections::HashMap;

pub struct Engine {
    tt: HashMap<u64, TTEntry>,
    killers: [[Option<Move>; 2]; 64],
    history: [[[u32; 64]; 64]; 2],
    book: OpeningBook,
}

impl Engine {
    pub fn new() -> Self {
        const EMPTY_KILLERS: [Option<Move>; 2] = [None, None];
        Self {
            tt: HashMap::with_capacity(2048 * 1024),
            killers: [EMPTY_KILLERS; 64],
            history: [[[0; 64]; 64]; 2],
            book: OpeningBook::new(),
        }
    }

    fn see_simple(&self, m: &Move, pos: &Chess) -> i32 {
        let victim = pos.board().piece_at(m.to()).map(|p| p.role).unwrap_or(Role::Pawn);
        let attacker = pos.board().piece_at(m.from().unwrap()).map(|p| p.role).unwrap_or(Role::Pawn);
        get_material_value(victim) - get_material_value(attacker) / 10
    }

    fn order_moves(&self, pos: &Chess, moves: &mut MoveList, hash_move: Option<&Move>, depth: u32) {
        let turn_idx = if pos.turn() == Color::White { 0 } else { 1 };
        moves.sort_by_cached_key(|m| {
            if let Some(hm) = hash_move {
                if m == hm { return -4000000; }
            }
            if m.is_capture() {
                return -2000000 - self.see_simple(m, pos);
            }
            
            if depth < 64 {
                if Some(m.clone()) == self.killers[depth as usize][0] { return -900000; }
                if Some(m.clone()) == self.killers[depth as usize][1] { return -800000; }
            }

            if let (Some(from), to) = (m.from(), m.to()) {
                let h_score = self.history[turn_idx][from as usize][to as usize];
                return -(h_score as i32);
            }

            if m.is_promotion() { return -700000; }
            0
        });
    }

    fn quiescence(&self, pos: &Chess, mut alpha: i32, beta: i32) -> i32 {
        let stand_pat = evaluate(pos);
        if stand_pat >= beta { return beta; }
        if alpha < stand_pat { alpha = stand_pat; }

        let mut captures = pos.legal_moves();
        captures.retain(|m| m.is_capture());
        self.order_moves(pos, &mut captures, None, 0);

        for m in captures {
            let mut next_pos = pos.clone();
            next_pos.play_unchecked(&m);
            let score = -self.quiescence(&next_pos, -beta, -alpha);
            
            if score >= beta { return beta; }
            if score > alpha { alpha = score; }
        }
        alpha
    }

    pub fn alpha_beta(&mut self, pos: &Chess, mut alpha: i32, mut beta: i32, mut depth: u32, ply: u32) -> i32 {
        let hash = pos.zobrist_hash::<Zobrist64>(shakmaty::EnPassantMode::Always).0;
        let is_check = pos.is_check();

        if is_check { depth += 1; }

        if let Some(entry) = self.tt.get(&hash) {
            if entry.depth >= depth {
                match entry.node_type {
                    NodeType::Exact => return entry.score,
                    NodeType::LowerBound => alpha = alpha.max(entry.score),
                    NodeType::UpperBound => beta = beta.min(entry.score),
                }
                if alpha >= beta { return entry.score; }
            }
        }

        if depth == 0 { return self.quiescence(pos, alpha, beta); }
        if pos.is_game_over() { return evaluate(pos); }

        if depth == 1 && !is_check {
            let static_eval = evaluate(pos);
            if static_eval - 160 >= beta { return beta; }
        }

        if depth >= 3 && !is_check && ply > 0 {
            let board = pos.board();
            let major_pieces = if pos.turn() == Color::White {
                (board.white() & !board.pawns() & !board.kings()).any()
            } else {
                (board.black() & !board.pawns() & !board.kings()).any()
            };

            if major_pieces {
                if let Ok(next_pos) = pos.clone().swap_turn() {
                    let score = -self.alpha_beta(&next_pos, -beta, -(beta - 1), depth - 3, ply + 1);
                    if score >= beta { return beta; }
                }
            }
        }

        let mut hash_move = self.tt.get(&hash).and_then(|e| e.best_move.as_ref());
        if hash_move.is_none() && depth >= 4 {
            self.alpha_beta(pos, alpha, beta, depth - 2, ply + 1);
            hash_move = self.tt.get(&hash).and_then(|e| e.best_move.as_ref());
        }

        let mut legals = pos.legal_moves();
        if legals.is_empty() {
            if is_check { return -30000 + ply as i32; }
            return 0;
        }

        self.order_moves(pos, &mut legals, hash_move, depth);

        let mut best_move_found = None;
        let mut best_score = -40000;
        let old_alpha = alpha;

        for (i, m) in legals.iter().enumerate() {
            let mut next_pos = pos.clone();
            next_pos.play_unchecked(m);
            
            let mut score;
            if i == 0 {
                score = -self.alpha_beta(&next_pos, -beta, -alpha, depth - 1, ply + 1);
            } else {
                if i >= 4 && depth >= 3 && !m.is_capture() && !is_check && !next_pos.is_check() {
                    let reduction = 1 + (i as u32 / 4).min(depth / 3);
                    score = -self.alpha_beta(&next_pos, -(alpha + 1), -alpha, depth - 1 - reduction, ply + 1);
                } else {
                    score = alpha + 1;
                }

                if score > alpha {
                    score = -self.alpha_beta(&next_pos, -(alpha + 1), -alpha, depth - 1, ply + 1);
                    if score > alpha && score < beta {
                        score = -self.alpha_beta(&next_pos, -beta, -alpha, depth - 1, ply + 1);
                    }
                }
            }
            
            if score > best_score {
                best_score = score;
                best_move_found = Some(m.clone());
            }

            alpha = alpha.max(score);
            if alpha >= beta {
                if !m.is_capture() && depth < 64 {
                    self.killers[depth as usize][1] = self.killers[depth as usize][0].clone();
                    self.killers[depth as usize][0] = Some(m.clone());
                    let turn_idx = if pos.turn() == Color::White { 0 } else { 1 };
                    if let (Some(from), to) = (m.from(), m.to()) {
                        self.history[turn_idx][from as usize][to as usize] += depth * depth;
                    }
                }
                break;
            }
        }

        let node_type = if best_score <= old_alpha { NodeType::UpperBound }
                        else if best_score >= beta { NodeType::LowerBound }
                        else { NodeType::Exact };

        self.tt.insert(hash, TTEntry { depth, score: best_score, node_type, best_move: best_move_found });
        best_score
    }

    pub fn find_best_move(&mut self, pos: &Chess, max_depth: u32) -> Option<Move> {
        if let Some(m_str) = self.book.get_move(pos) {
            if let Ok(uci_move) = m_str.parse::<shakmaty::uci::UciMove>() {
                if let Ok(m) = uci_move.to_move(pos) {
                    return Some(m);
                }
            }
        }

        let mut overall_best_move = None;
        let mut alpha = -40000;
        let mut beta = 40000;

        for depth in 1..=max_depth {
            let score = self.alpha_beta(pos, alpha, beta, depth, 0);

            if score <= alpha || score >= beta {
                alpha = -40000;
                beta = 40000;
                let _ = self.alpha_beta(pos, alpha, beta, depth, 0);
            } else {
                alpha = score - 50;
                beta = score + 50;
            }

            let hash = pos.zobrist_hash::<Zobrist64>(shakmaty::EnPassantMode::Always).0;
            if let Some(entry) = self.tt.get(&hash) {
                if let Some(ref m) = entry.best_move {
                    overall_best_move = Some(m.clone());
                }
            }
        }
        overall_best_move
    }
}