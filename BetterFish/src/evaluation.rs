use shakmaty::{Chess, Role, Position, Square, Color, Bitboard, Rank};
use crate::constants::*;

fn get_pst_value(role: Role, color: Color, square: Square, phase: i32) -> i32 {
    let index = if color == Color::White {
        (7 - square.rank() as usize) * 8 + (square.file() as usize)
    } else {
        (square.rank() as usize) * 8 + (square.file() as usize)
    };

    let (mg, eg) = match role {
        Role::Pawn => (MG_PAWN_PST[index], EG_PAWN_PST[index]),
        Role::Knight => (MG_KNIGHT_PST[index], MG_KNIGHT_PST[index]),
        Role::Bishop => (MG_BISHOP_PST[index], MG_BISHOP_PST[index]),
        Role::Rook => (ROOK_PST[index], ROOK_PST[index]),
        Role::Queen => (QUEEN_PST[index], QUEEN_PST[index]),
        Role::King => (MG_KING_PST[index], EG_KING_PST[index]),
    };

    ((mg * (256 - phase)) + (eg * phase)) / 256
}

pub fn evaluate(pos: &Chess) -> i32 {
    if pos.is_game_over() {
        if pos.is_checkmate() { return -30000; }
        return 0;
    }

    let board = pos.board();
    let turn = pos.turn();
    
    let n_knights = board.knights().count();
    let n_bishops = board.bishops().count();
    let n_rooks = board.rooks().count();
    let n_queens = board.queens().count();
    
    let total_phase = 24; 
    let mut phase = total_phase - (n_knights + n_bishops + n_rooks * 2 + n_queens * 4) as i32;
    phase = (phase * 256 + (total_phase / 2)) / total_phase;

    let mut score = 0;
    
    let white_pawns = board.pawns() & board.white();
    let black_pawns = board.pawns() & board.black();

    for square in board.occupied() {
        if let Some(piece) = board.piece_at(square) {
            let mut val = get_material_value(piece.role);
            val += get_pst_value(piece.role, piece.color, square, phase);

            match piece.role {
                Role::Rook => {
                    let file_bb = Bitboard::from_file(square.file());
                    if (board.pawns() & file_bb).is_empty() {
                        val += ROOK_ON_OPEN_FILE;
                    }
                    // Rook on 7th rank
                    let seventh = if piece.color == Color::White { Rank::Seventh } else { Rank::Second };
                    if square.rank() == seventh {
                        val += ROOK_ON_7TH_BONUS;
                    }
                },
                Role::Knight => {
                    // Knight outpost
                    let rank_idx = square.rank() as i32;
                    let is_central_file = square.file() as i32 >= 2 && square.file() as i32 <= 5;
                    let is_advanced = if piece.color == Color::White { rank_idx >= 3 } else { rank_idx <= 4 };
                    if is_central_file && is_advanced {
                        let adj_files = square.file().offset(-1).map_or(Bitboard(0), Bitboard::from_file) |
                                        square.file().offset(1).map_or(Bitboard(0), Bitboard::from_file);
                        let is_defended = !(board.pawns() & board.by_color(piece.color) & adj_files).is_empty();
                        if is_defended {
                            val += KNIGHT_OUTPOST_BONUS;
                        }
                    }
                },
                Role::King => {
                    if phase < 128 {
                        let shield_rank = if piece.color == Color::White { Rank::Second } else { Rank::Seventh };
                        let shield_mask = Bitboard::from_rank(shield_rank) & 
                                          (Bitboard::from_file(square.file()) | 
                                           square.file().offset(-1).map_or(Bitboard(0), Bitboard::from_file) |
                                           square.file().offset(1).map_or(Bitboard(0), Bitboard::from_file));
                        let shield_count = (board.pawns() & board.by_color(piece.color) & shield_mask).count();
                        val += shield_count as i32 * KING_SHIELD_BONUS;
                    }
                },
                Role::Pawn => {
                    let color = piece.color;
                    let my_pawns = if color == Color::White { white_pawns } else { black_pawns };
                    let enemy_pawns = if color == Color::White { black_pawns } else { white_pawns };

                    if (my_pawns & Bitboard::from_file(square.file())).count() > 1 {
                        val += DOUBLED_PAWN_PENALTY;
                    }

                    let adj_files = square.file().offset(-1).map_or(Bitboard(0), Bitboard::from_file) |
                                    square.file().offset(1).map_or(Bitboard(0), Bitboard::from_file);
                    if (my_pawns & adj_files).is_empty() {
                        val += ISOLATED_PAWN_PENALTY;
                    }

                    let mut ahead = Bitboard(0);
                    if color == Color::White {
                        for r in (square.rank() as i8 + 1)..8 {
                            ahead |= Bitboard::from_rank(Rank::new(r as u32));
                        }
                    } else {
                        for r in 0..(square.rank() as i8) {
                            ahead |= Bitboard::from_rank(Rank::new(r as u32));
                        }
                    }
                    if (enemy_pawns & (Bitboard::from_file(square.file()) | adj_files) & ahead).is_empty() {
                        let rel_rank = if color == Color::White { square.rank() as usize } else { 7 - square.rank() as usize };
                        val += PASSED_PAWN_BONUS[rel_rank];
                    }
                },
                _ => {}
            }

            if piece.color == turn {
                score += val;
            } else {
                score -= val;
            }
        }
    }

    let white_bishops = (board.bishops() & board.white()).count();
    let black_bishops = (board.bishops() & board.black()).count();
    if turn == Color::White {
        if white_bishops >= 2 { score += 50; }
        if black_bishops >= 2 { score -= 50; }
    } else {
        if black_bishops >= 2 { score += 50; }
        if white_bishops >= 2 { score -= 50; }
    }

    // Dynamic mobility weighting
    let mobility = pos.legal_moves().len() as i32;
    score += mobility / 2;

    score
}
