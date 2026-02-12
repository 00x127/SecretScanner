use shakmaty::{Chess, EnPassantMode};
use shakmaty::fen::Epd;
use std::collections::HashMap;

pub struct OpeningBook {
    book: HashMap<String, Vec<String>>,
}

impl OpeningBook {
    pub fn new() -> Self {
        let mut book = HashMap::new();
        let mut add = |fen: &str, m_str: &str| {
            book.entry(fen.to_string()).or_insert_with(Vec::new).push(m_str.to_string());
        };

        // --- STARTING POSITION ---
        let start = "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq -";
        for m in &["e2e4", "d2d4", "c2c4", "g1f3", "b1c3", "f2f4", "b2b3", "g2g3"] { add(start, m); }

        // --- 1. e4 OPENINGS ---
        let e4 = "rnbqkbnr/pppppppp/8/8/4P3/8/PPPP1PPP/RNBQKBNR b KQkq -";
        for m in &["c7c5", "e7e5", "e7e6", "c7c6", "d7d5", "g8f6", "d7d6", "g7g6", "b7b6", "a7a6", "h7h6"] { add(e4, m); }

        // --- 1. d4 OPENINGS ---
        let d4 = "rnbqkbnr/pppppppp/8/8/3P4/8/PPP1PPPP/RNBQKBNR b KQkq -";
        for m in &["g8f6", "d7d5", "f7f5", "e7e6", "c7c6", "g7g6", "d7d6"] { add(d4, m); }

        // --- 1. c4 (English) ---
        let c4 = "rnbqkbnr/pppppppp/8/8/2P5/8/PP1PPPPP/RNBQKBNR b KQkq -";
        for m in &["e7e5", "c7c5", "g8f6", "e7e6"] { add(c4, m); }

        // --- 1. f3 (Reti) ---
        let nf3 = "rnbqkbnr/pppppppp/8/8/8/5N2/PPPPPPPP/RNBQKB1R b KQkq -";
        for m in &["d7d5", "g8f6", "c7c5"] { add(nf3, m); }

        // --- SICILIAN DEFENSE (1. e4 c5) ---
        let sicilian = "rnbqkbnr/pp1ppppp/8/2p5/4P3/8/PPPP1PPP/RNBQKBNR w KQkq -";
        for m in &["g1f3", "b1c3", "d2d3", "c2c3"] { add(sicilian, m); }
        
        // Open Sicilian (2. Nf3)
        let open_sicilian = "rnbqkbnr/pp1ppppp/8/2p5/4P3/5N2/PPPP1PPP/RNBQKB1R b KQkq -";
        for m in &["d7d6", "e7e6", "b8c6", "g7g6", "a7a6"] { add(open_sicilian, m); }

        // Najdorf (1. e4 c5 2. Nf3 d6 3. d4 cxd4 4. Nxd4 Nf6 5. Nc3 a6)
        let najdorf_pos = "r1bqkb1r/1p2pppp/p2p1n2/8/3NP3/2N5/PPP2PPP/R1BQKB1R w KQkq -";
        for m in &["c1g5", "f2f4", "f1e2", "h2h3", "g2g4", "a2a4"] { add(najdorf_pos, m); }

        // --- RUY LOPEZ (1. e4 e5 2. Nf3 Nc6 3. Bb5) ---
        let ruy_lopez = "r1bqkbnr/pppp1ppp/2n5/1B2p3/4P3/5N2/PPPP1PPP/RNBQK2R b KQkq -";
        for m in &["a7a6", "g8f6", "d7d6", "f7f5", "g7g6", "b8c6"] { add(ruy_lopez, m); }

        // Morphay Defense (3... a6)
        let morphay = "r1bqkbnr/1ppp1ppp/p1n5/1B2p3/4P3/5N2/PPPP1PPP/RNBQK2R w KQkq -";
        for m in &["b5a4", "b5xc6"] { add(morphay, m); }

        // Exchange Variation (4. Bxc6)
        let ruy_exchange = "r1bqkbnr/1ppp1ppp/2N5/4p3/4P3/5N2/PPPP1PPP/RNBQK2R b KQkq -";
        for m in &["d7xc6", "b7xc6"] { add(ruy_exchange, m); }

        // --- ITALIAN GAME (1. e4 e5 2. Nf3 Nc6 3. Bc4) ---
        let italian = "r1bqkbnr/pppp1ppp/2n5/4p3/2B1P3/5N2/PPPP1PPP/RNBQK2R b KQkq -";
        for m in &["f8c5", "g8f6", "h7h6"] { add(italian, m); }

        // --- FRENCH DEFENSE (1. e4 e6 2. d4 d5) ---
        let french = "rnbqkbnr/pppp1ppp/4p3/8/3PP3/8/PPP2PPP/RNBQKBNR b KQkq -";
        for m in &["d7d5", "c7c5"] { add(french, m); }
        
        let french_main = "rnbqkbnr/ppp2ppp/4p3/3p4/3PP3/8/PPP2PPP/RNBQKBNR w KQkq -";
        for m in &["b1c3", "b1d2", "e4e5", "e4xd5"] { add(french_main, m); }

        // --- QUEEN'S GAMBIT (1. d4 d5 2. c4) ---
        let qg = "rnbqkbnr/ppp1pppp/8/3p4/2PP4/8/PP2PPPP/RNBQKBNR b KQkq -";
        for m in &["e7e6", "c7c6", "d5xc4", "e7e5", "g8f6"] { add(qg, m); }

        // --- KING'S INDIAN (1. d4 Nf6 2. c4 g6) ---
        let kid = "rnbqkb1r/pppppp1p/5np1/8/2PP4/8/PP2PPPP/RNBQKBNR w KQkq -";
        for m in &["b1c3", "g1f3", "g2g3"] { add(kid, m); }

        // --- CARO-KANN (1. e4 c6 2. d4 d5) ---
        let caro_kann = "rnbqkbnr/pp1ppppp/2p5/8/3PP3/8/PPP2PPP/RNBQKBNR b KQkq -";
        for m in &["d7d5"] { add(caro_kann, m); }
        
        let caro_main = "rnbqkbnr/pp2pppp/2p5/3p4/3PP3/8/PPP2PPP/RNBQKBNR w KQkq -";
        for m in &["b1c3", "e4e5", "e4xd5", "b1d2"] { add(caro_main, m); }

        // --- SCANDINAVIAN (1. e4 d5 2. exd5 Qxd5) ---
        let scandi_open = "rnbqkbnr/ppp1pppp/8/3P4/8/8/PPPP1PPP/RNBQKBNR b KQkq -";
        for m in &["d8xd5", "g8f6"] { add(scandi_open, m); }

        // --- LONDON SYSTEM (1. d4 d5 2. Bf4) ---
        let london = "rnbqkbnr/ppp1pppp/8/3p4/3P1B2/8/PPP1PPPP/RN1QKBNR b KQkq -";
        for m in &["g8f6", "c7c5", "e7e6"] { add(london, m); }

        // --- NIMZO-INDIAN (1. d4 Nf6 2. c4 e6 3. Nc3 Bb4) ---
        let nimzo = "rnbqkb1r/pppp1ppp/4pn2/8/2PP4/2N5/PP2PPPP/R1BQKBNR b KQkq -";
        for m in &["f8b4", "d7d5", "c7c5"] { add(nimzo, m); }

        // --- GRUENFELD (1. d4 Nf6 2. c4 g6 3. Nc3 d5) ---
        let gruenfeld = "rnbqkb1r/ppp1pp1p/5np1/3p4/2PP4/2N5/PP2PPPP/R1BQKBNR w KQkq -";
        for m in &["c4xd5", "g1f3", "c1f4", "c1g5"] { add(gruenfeld, m); }

        // --- BENONI (1. d4 Nf6 2. c4 c5 3. d5) ---
        let benoni = "rnbqkb1r/pppppppp/5n2/2pP4/8/8/PP2PPPP/RNBQKBNR b KQkq -";
        for m in &["e7e6", "d7d6", "g7g6"] { add(benoni, m); }

        // --- DUTCH DEFENSE (1. d4 f5) ---
        let dutch = "rnbqkbnr/ppppp1pp/8/5p2/3P4/8/PPP1PPPP/RNBQKBNR w KQkq -";
        for m in &["c2c4", "g1f3", "g2g3", "c1g5"] { add(dutch, m); }

        // --- CATALAN (1. d4 Nf6 2. c4 e6 3. g3 d5) ---
        let catalan = "rnbqkb1r/ppp2ppp/4pn2/3p4/2PP4/6P1/PP2PP1P/RNBQKBNR w KQkq -";
        for m in &["f1g2", "g1f3"] { add(catalan, m); }

        Self { book }
    }

    pub fn get_move(&self, pos: &Chess) -> Option<String> {
        let epd = Epd::from_position(pos.clone(), EnPassantMode::Always);
        let epd_string = format!("{}", epd);
        let parts: Vec<&str> = epd_string.split_whitespace().collect();
        if parts.len() >= 4 {
            let key = parts[0..4].join(" ");
            if let Some(moves) = self.book.get(&key) {
                let idx = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() % moves.len() as u128) as usize;
                return Some(moves[idx].clone());
            }
        }
        None
    }
}