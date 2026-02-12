mod evaluation;
mod engine;
mod constants;
mod tt;
mod opening_book;

use shakmaty::{Chess, Position};
use std::io::{self, BufRead};
use crate::engine::Engine;

fn main() {
    let stdin = io::stdin();
    let mut pos = Chess::default();
    let depth = 6; // Increased depth
    let mut engine = Engine::new();

    for line in stdin.lock().lines() {
        let line = line.unwrap();
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() { continue; }

        match parts[0] {
            "uci" => {
                println!("id name BetterFish");
                println!("id author Gemini CLI");
                println!("uciok");
            }
            "isready" => println!("readyok"),
            "ucinewgame" => {
                pos = Chess::default();
                engine = Engine::new();
            }
            "position" => {
                if parts.len() > 1 {
                    if parts[1] == "startpos" {
                        pos = Chess::default();
                        if parts.len() > 2 && parts[2] == "moves" {
                            update_position(&mut pos, &parts[3..]);
                        }
                    } else if parts[1] == "fen" {
                        let fen_str = parts[2..8].join(" ");
                        if let Ok(p) = fen_str.parse::<shakmaty::fen::Fen>() {
                            if let Ok(p_chess) = p.into_position::<Chess>(shakmaty::CastlingMode::Standard) {
                                pos = p_chess;
                            }
                        }
                        if let Some(moves_idx) = parts.iter().position(|&r| r == "moves") {
                            update_position(&mut pos, &parts[moves_idx + 1..]);
                        }
                    }
                }
            }
            "go" => {
                let best_move = engine.find_best_move(&pos, depth);
                if let Some(m) = best_move {
                    println!("bestmove {}", m.to_uci(shakmaty::CastlingMode::Standard));
                }
            }
            "quit" => break,
            _ => {}
        }
    }
}

fn update_position(pos: &mut Chess, moves: &[&str]) {
    for m_str in moves {
        if let Ok(m) = m_str.parse::<shakmaty::uci::UciMove>() {
            if let Ok(m_actual) = m.to_move(pos) {
                pos.play_unchecked(&m_actual);
            }
        }
    }
}