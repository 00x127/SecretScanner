const socket = io();
const game = new Chess();
const boardElement = document.getElementById('board');
const statusElement = document.getElementById('status');
const resetBtn = document.getElementById('resetBtn');
const flipBtn = document.getElementById('flipBtn');
const startBtn = document.getElementById('startBtn');
const settingsBtn = document.getElementById('settingsBtn');
const setupArea = document.getElementById('setup-area');
const modal = document.getElementById('game-over-modal');
const settingsModal = document.getElementById('settings-modal');
const closeSettingsBtn = document.getElementById('close-settings');
const modalResetBtn = document.getElementById('modal-reset-btn');

const engineEloInput = document.getElementById('engine-elo');
const engineDepthInput = document.getElementById('engine-depth');
const eloValSpan = document.getElementById('elo-val');
const depthValSpan = document.getElementById('depth-val');
const opponentTypeSelect = document.getElementById('opponent-type');

let selectedSquare = null;
let orientation = 'white'; // 'white' or 'black'
let pendingMove = null;
let gameStarted = false;
let rightClickHighlights = new Set();

// --- Engine Logic ---
let stockfish = null;

function initEngine() {
    if (stockfish) stockfish.terminate();
    // Stockfish.js typically exposes a global Stockfish() function or can be used as a worker
    try {
        stockfish = new Worker('https://cdn.jsdelivr.net/npm/stockfish/src/stockfish.js');
    } catch (e) {
        console.error("Could not load Stockfish worker", e);
        return;
    }
    
    stockfish.onmessage = (event) => {
        const line = event.data;
        if (line.startsWith('bestmove')) {
            const moveStr = line.split(' ')[1];
            if (moveStr !== '(none)') {
                makeEngineMove(moveStr);
            }
        }
    };

    stockfish.postMessage('uci');
}

function makeEngineMove(moveStr) {
    const from = moveStr.substring(0, 2);
    const to = moveStr.substring(2, 4);
    const promotion = moveStr.length > 4 ? moveStr.substring(4, 5) : 'q';
    
    const move = game.move({ from, to, promotion });
    if (move) {
        onMoveComplete(move);
    }
}

function triggerEngine() {
    if (!gameStarted || opponentTypeSelect.value !== 'ai' || !stockfish) return;
    if (game.turn() === orientation[0]) return; // Not AI's turn

    const depth = engineDepthInput.value;
    const elo = engineEloInput.value;
    
    stockfish.postMessage(`setoption name UCI_LimitStrength value true`);
    stockfish.postMessage(`setoption name UCI_Elo value ${elo}`);
    stockfish.postMessage(`position fen ${game.fen()}`);
    stockfish.postMessage(`go depth ${depth}`);
}

// --- Settings ---
settingsBtn.addEventListener('click', () => {
    settingsModal.style.display = 'flex';
});

closeSettingsBtn.addEventListener('click', () => {
    settingsModal.style.display = 'none';
});

engineEloInput.addEventListener('input', () => eloValSpan.innerText = engineEloInput.value);
engineDepthInput.addEventListener('input', () => depthValSpan.innerText = engineDepthInput.value);

// --- Right-Click Highlighting ---
boardElement.oncontextmenu = (e) => {
    e.preventDefault();
    const square = e.target.closest('.square');
    if (square) {
        const id = square.dataset.square;
        if (rightClickHighlights.has(id)) {
            rightClickHighlights.delete(id);
            square.classList.remove('highlight-red');
        } else {
            rightClickHighlights.add(id);
            square.classList.add('highlight-red');
        }
    }
};

// --- Resign / Draw ---
resignBtn.addEventListener('click', () => {
    if (!gameStarted) return;
    if (confirm('Are you sure you want to resign?')) {
        socket.emit('resign');
        onGameOver('Opponent wins', 'by resignation');
    }
});

drawBtn.addEventListener('click', () => {
    if (!gameStarted) return;
    socket.emit('draw_offer');
});

socket.on('resign', () => {
    onGameOver('You win', 'by resignation');
});

socket.on('draw_offer', () => {
    if (confirm('Opponent offers a draw. Accept?')) {
        socket.emit('draw_accept');
        onGameOver('Draw', 'by agreement');
    }
});

socket.on('draw_accept', () => {
    onGameOver('Draw', 'by agreement');
});

function onGameOver(winner, reason) {
    gameStarted = false;
    winTxt.innerText = winner.toUpperCase();
    reasonTxt.innerText = reason;
    modal.style.display = 'flex';
    playSound('game-end');
    if (timerInterval) clearInterval(timerInterval);
}

// --- Start Game ---
startBtn.addEventListener('click', () => {
    const selectedColor = document.querySelector('input[name="player-color"]:checked').value;
    orientation = selectedColor;
    gameStarted = true;
    
    startBtn.classList.add('disabled');
    setupArea.style.opacity = '0.5';
    setupArea.style.pointerEvents = 'none';
    
    if (opponentTypeSelect.value === 'ai') {
        initEngine();
    }
    
    renderBoard();
    if (game.turn() === 'w') {
        startTimer();
    }

    // If AI is white and we are black, AI moves immediately
    if (opponentTypeSelect.value === 'ai' && orientation === 'black') {
        setTimeout(triggerEngine, 1000);
    }
});

// --- Timer Logic ---
let timers = { w: 600, b: 600 }; // 10 minutes in seconds
let timerInterval = null;

function startTimer() {
    if (timerInterval) clearInterval(timerInterval);
    timerInterval = setInterval(() => {
        if (game.game_over()) {
            clearInterval(timerInterval);
            return;
        }
        
        const turn = game.turn();
        timers[turn]--;
        
        if (timers[turn] <= 0) {
            timers[turn] = 0;
            clearInterval(timerInterval);
            onTimeOut(turn);
        }
        
        updateClocks();
    }, 1000);
}

function updateClocks() {
    const formatTime = (s) => {
        const mins = Math.floor(s / 60);
        const secs = s % 60;
        return `${mins}:${secs.toString().padStart(2, '0')}`;
    };
    
    const clockW = document.getElementById('clock-w');
    const clockB = document.getElementById('clock-b');
    
    clockW.innerText = formatTime(timers.w);
    clockB.innerText = formatTime(timers.b);
    
    clockW.classList.toggle('active', game.turn() === 'w');
    clockB.classList.toggle('active', game.turn() === 'b');
    
    if (timers.w < 30) clockW.classList.add('low-time');
    if (timers.b < 30) clockB.classList.add('low-time');
}

function onTimeOut(color) {
    const winner = color === 'w' ? 'Black' : 'White';
    winTxt.innerText = `${winner.toUpperCase()} WINS!`;
    reasonTxt.innerText = 'on time';
    modal.style.display = 'flex';
    playSound('game-end');
}

// --- Promotion ---
function showPromotionModal(color) {
    const pieces = ['q', 'r', 'b', 'n'];
    const container = promotionModal.querySelector('.promotion-content');
    container.innerHTML = '';
    
    pieces.forEach(p => {
        const el = document.createElement('div');
        el.classList.add('promotion-piece');
        el.classList.add(`${p}-${color}`);
        el.dataset.piece = p;
        el.addEventListener('click', () => {
            const move = game.move({
                from: pendingMove.from,
                to: pendingMove.to,
                promotion: p
            });
            promotionModal.style.display = 'none';
            pendingMove = null;
            onMoveComplete(move);
        });
        container.appendChild(el);
    });
    
    promotionModal.style.display = 'flex';
}

function onMoveComplete(move) {
    selectedSquare = null;
    rightClickHighlights.clear();
    
    // Play sound
    if (game.in_checkmate() || game.in_draw()) {
        playSound('game-end');
    } else if (game.in_check()) {
        playSound('check');
    } else if (move.captured) {
        playSound('capture');
    } else {
        playSound('move');
    }

    renderBoard();
    socket.emit('move', { fen: game.fen() });
    startTimer();

    // Trigger AI if it's their turn
    if (opponentTypeSelect.value === 'ai') {
        setTimeout(triggerEngine, 500);
    }
}

// --- Game Logic & UI ---

function renderBoard() {
    boardElement.innerHTML = '';
    const isFlipped = orientation === 'black';

    // Loop rows and cols
    for (let r = 0; r < 8; r++) {
        for (let c = 0; c < 8; c++) {
            // If flipped, start from 7 down to 0
            const row = isFlipped ? r : 7 - r;
            const col = isFlipped ? 7 - c : c;

            const squareId = String.fromCharCode(97 + col) + (row + 1); // e.g., 'a1'
            const piece = game.get(squareId);
            
            const squareEl = document.createElement('div');
            squareEl.classList.add('square');
            // Determine color (light or dark)
            const isLight = (row + col) % 2 !== 0;
            squareEl.classList.add(isLight ? 'light' : 'dark');
            squareEl.dataset.square = squareId;

            // Add coordinates
            const showRank = c === 0;
            const showFile = r === 7;
            if (showRank) {
                squareEl.dataset.rank = row + 1;
                squareEl.classList.add('coord-rank');
            }
            if (showFile) {
                squareEl.dataset.file = String.fromCharCode(97 + col);
                squareEl.classList.add('coord-file');
            }

            // Highlight selected
            if (selectedSquare === squareId) {
                squareEl.classList.add('selected');
            }

            // Highlight right-click
            if (rightClickHighlights.has(squareId)) {
                squareEl.classList.add('highlight-red');
            }

            // Highlight legal moves
            if (selectedSquare) {
                const moves = game.moves({ square: selectedSquare, verbose: true });
                if (moves.some(m => m.to === squareId)) {
                    const isCapture = game.get(squareId) !== null;
                    squareEl.classList.add(isCapture ? 'capture-hint' : 'move-hint');
                }
            }

            // Highlight last move
            const history = game.history({ verbose: true });
            if (history.length > 0) {
                const lastMove = history[history.length - 1];
                if (lastMove.from === squareId || lastMove.to === squareId) {
                    squareEl.classList.add('highlight');
                }
            }

            // Highlight Check
            if (game.in_check() && piece && piece.type === 'k' && piece.color === game.turn()) {
                squareEl.classList.add('check');
            }

            // Add piece if exists
            if (piece) {
                const pieceEl = document.createElement('div');
                pieceEl.classList.add('piece');
                pieceEl.classList.add(piece.type + '-' + piece.color); // e.g., 'p-w'
                pieceEl.draggable = true;
                
                pieceEl.addEventListener('dragstart', (e) => {
                    if (!gameStarted) {
                        e.preventDefault();
                        return;
                    }
                    selectedSquare = squareId;
                    e.dataTransfer.setData('text/plain', squareId);
                    // Add a small delay so the piece doesn't disappear immediately
                    setTimeout(() => pieceEl.style.opacity = '0.5', 0);
                    renderBoard(); // Show hints
                });
                
                pieceEl.addEventListener('dragend', () => {
                    pieceEl.style.opacity = '1';
                });

                squareEl.appendChild(pieceEl);
            }

            // Event Listeners for Drag and Drop
            squareEl.addEventListener('dragover', (e) => {
                e.preventDefault();
            });

            squareEl.addEventListener('drop', (e) => {
                e.preventDefault();
                const fromSquare = e.dataTransfer.getData('text/plain');
                onSquareClick(squareId); // Reuse logic
            });

            // Event Listener
            squareEl.addEventListener('click', () => onSquareClick(squareId));

            boardElement.appendChild(squareEl);
        }
    }
    updateStatus();
    updateUI();
    updateClocks();
}

function updateUI() {
    // ... previous code ...
    // (I'll replace the whole function for clarity in the next step or part of it)
    const history = game.history();
    const historyEl = document.getElementById('move-history');
    historyEl.innerHTML = '';
    
    for (let i = 0; i < history.length; i += 2) {
        const moveRow = document.createElement('div');
        moveRow.classList.add('move-row');
        
        const moveNum = document.createElement('div');
        moveNum.classList.add('move-num');
        moveNum.innerText = (i / 2 + 1) + '.';
        
        const moveWhite = document.createElement('div');
        moveWhite.classList.add('move-white');
        moveWhite.innerText = history[i];
        
        moveRow.appendChild(moveNum);
        moveRow.appendChild(moveWhite);
        
        if (history[i + 1]) {
            const moveBlack = document.createElement('div');
            moveBlack.classList.add('move-black');
            moveBlack.innerText = history[i + 1];
            moveRow.appendChild(moveBlack);
        }
        
        historyEl.appendChild(moveRow);
    }
    historyEl.scrollTop = historyEl.scrollHeight;

    // Update Captured Pieces
    const capturedByWhiteEl = document.getElementById('captured-b'); // Pieces white has taken
    const capturedByBlackEl = document.getElementById('captured-w'); // Pieces black has taken
    capturedByWhiteEl.innerHTML = '';
    capturedByBlackEl.innerHTML = '';

    const pieceValues = { p: 1, n: 3, b: 3, r: 5, q: 9 };
    const initialPieces = { p: 8, n: 2, b: 2, r: 2, q: 1 };
    
    const currentPieces = {
        w: { p: 0, n: 0, b: 0, r: 0, q: 0, k: 0 },
        b: { p: 0, n: 0, b: 0, r: 0, q: 0, k: 0 }
    };

    game.board().forEach(row => {
        row.forEach(p => {
            if (p) currentPieces[p.color][p.type]++;
        });
    });

    let whiteValueTaken = 0;
    let blackValueTaken = 0;

    const renderCaptured = (color, container) => {
        let totalVal = 0;
        ['p', 'n', 'b', 'r', 'q'].forEach(type => {
            const taken = initialPieces[type] - currentPieces[color][type];
            for (let i = 0; i < taken; i++) {
                const el = document.createElement('div');
                el.classList.add('captured-piece');
                el.classList.add(`${type}-${color}`);
                container.appendChild(el);
                totalVal += pieceValues[type];
            }
        });
        return totalVal;
    };

    whiteValueTaken = renderCaptured('w', capturedByBlackEl); // Black took these white pieces
    blackValueTaken = renderCaptured('b', capturedByWhiteEl); // White took these black pieces

    // Advantage is for the one who took MORE value
    if (blackValueTaken > whiteValueTaken) {
        // White is winning
        const span = document.createElement('span');
        span.classList.add('advantage');
        span.innerText = `+${blackValueTaken - whiteValueTaken}`;
        capturedByWhiteEl.appendChild(span);
    } else if (whiteValueTaken > blackValueTaken) {
        // Black is winning
        const span = document.createElement('span');
        span.classList.add('advantage');
        span.innerText = `+${whiteValueTaken - blackValueTaken}`;
        capturedByBlackEl.appendChild(span);
    }
}

// --- Audio ---
const audioCtx = new (window.AudioContext || window.webkitAudioContext)();

function playSound(type) {
    const oscillator = audioCtx.createOscillator();
    const gainNode = audioCtx.createGain();

    oscillator.connect(gainNode);
    gainNode.connect(audioCtx.destination);

    const now = audioCtx.currentTime;

    if (type === 'move') {
        oscillator.type = 'triangle';
        oscillator.frequency.setValueAtTime(200, now);
        oscillator.frequency.exponentialRampToValueAtTime(100, now + 0.1);
        gainNode.gain.setValueAtTime(0.1, now);
        gainNode.gain.exponentialRampToValueAtTime(0.01, now + 0.1);
        oscillator.start(now);
        oscillator.stop(now + 0.1);
    } else if (type === 'capture') {
        oscillator.type = 'square';
        oscillator.frequency.setValueAtTime(150, now);
        oscillator.frequency.exponentialRampToValueAtTime(80, now + 0.15);
        gainNode.gain.setValueAtTime(0.05, now);
        gainNode.gain.exponentialRampToValueAtTime(0.01, now + 0.15);
        oscillator.start(now);
        oscillator.stop(now + 0.15);
    } else if (type === 'check') {
        oscillator.type = 'sine';
        oscillator.frequency.setValueAtTime(440, now);
        oscillator.frequency.exponentialRampToValueAtTime(880, now + 0.1);
        gainNode.gain.setValueAtTime(0.1, now);
        gainNode.gain.exponentialRampToValueAtTime(0.01, now + 0.2);
        oscillator.start(now);
        oscillator.stop(now + 0.2);
    } else if (type === 'game-end') {
        oscillator.type = 'sine';
        oscillator.frequency.setValueAtTime(220, now);
        oscillator.frequency.exponentialRampToValueAtTime(440, now + 0.5);
        gainNode.gain.setValueAtTime(0.1, now);
        gainNode.gain.exponentialRampToValueAtTime(0.01, now + 0.5);
        oscillator.start(now);
        oscillator.stop(now + 0.5);
    }
}

function onSquareClick(squareId) {
    if (!gameStarted) return;
    
    const piece = game.get(squareId);

    // If we have a selected square, try to move
    if (selectedSquare) {
        // If clicked same square, deselect
        if (selectedSquare === squareId) {
            selectedSquare = null;
            renderBoard();
            return;
        }

        const pieceAtFrom = game.get(selectedSquare);
        const isPawn = pieceAtFrom && pieceAtFrom.type === 'p';
        const isPromotionRank = (pieceAtFrom && pieceAtFrom.color === 'w' && squareId[1] === '8') ||
                                (pieceAtFrom && pieceAtFrom.color === 'b' && squareId[1] === '1');

        if (isPawn && isPromotionRank) {
            // Validate if move is legal first
            const moves = game.moves({ square: selectedSquare, verbose: true });
            if (moves.some(m => m.to === squareId)) {
                pendingMove = { from: selectedSquare, to: squareId };
                showPromotionModal(pieceAtFrom.color);
                return;
            }
        }

        // Try move
        const move = game.move({
            from: selectedSquare,
            to: squareId,
            promotion: 'q' // Default for non-promotion clicks if somehow triggered
        });

        if (move) {
            onMoveComplete(move);
        } else {
            // Invalid move. 
            // If clicked on another of our pieces, switch selection
            if (piece && piece.color === game.turn()) {
                selectedSquare = squareId;
                renderBoard();
            } else {
                selectedSquare = null;
                renderBoard();
            }
        }
    } else {
        // No selection. Select if it's a piece of current turn
        if (piece && piece.color === game.turn()) {
            selectedSquare = squareId;
            renderBoard();
        }
    }
}

function updateStatus() {
    let status = '';

    if (game.in_checkmate()) {
        const winner = game.turn() === 'w' ? 'Black' : 'White';
        status = `Game over, ${winner} wins by checkmate.`;
        winTxt.innerText = `${winner.toUpperCase()} WINS!`;
        reasonTxt.innerText = 'by checkmate';
        modal.style.display = 'flex';
    } else if (game.in_draw()) {
        status = 'Game over, drawn position';
        winTxt.innerText = 'DRAW';
        reasonTxt.innerText = 'stalemate or insufficient material';
        modal.style.display = 'flex';
    } else {
        status = (game.turn() === 'w' ? 'White' : 'Black') + ' to move';
        if (game.in_check()) {
            status += ', ' + (game.turn() === 'w' ? 'White' : 'Black') + ' is in check';
        }
        modal.style.display = 'none';
    }
    statusElement.innerText = status;
}

// --- Socket.io Events ---

socket.on('init', (serverState) => {
    // Load state
    game.load(serverState.fen);
    renderBoard();
});

socket.on('move', (moveData) => {
    const oldFen = game.fen();
    game.load(moveData.fen);
    
    if (!gameStarted) {
        gameStarted = true;
        startBtn.classList.add('disabled');
        setupArea.style.opacity = '0.5';
        setupArea.style.pointerEvents = 'none';
    }

    // Determine sound to play
    if (game.in_checkmate() || game.in_draw()) {
        playSound('game-end');
    } else if (game.in_check()) {
        playSound('check');
    } else {
        playSound('move');
    }

    renderBoard();
    startTimer();
});

socket.on('reset', () => {
    game.reset();
    timers = { w: 600, b: 600 };
    updateClocks();
    if (timerInterval) clearInterval(timerInterval);
    gameStarted = false;
    startBtn.classList.remove('disabled');
    setupArea.style.opacity = '1';
    setupArea.style.pointerEvents = 'all';
    selectedSquare = null;
    renderBoard();
});

// --- Controls ---

resetBtn.addEventListener('click', () => {
    game.reset();
    timers = { w: 600, b: 600 };
    updateClocks();
    if (timerInterval) clearInterval(timerInterval);
    gameStarted = false;
    startBtn.classList.remove('disabled');
    setupArea.style.opacity = '1';
    setupArea.style.pointerEvents = 'all';
    renderBoard();
    socket.emit('reset');
    modal.style.display = 'none';
});

flipBtn.addEventListener('click', () => {
    orientation = orientation === 'white' ? 'black' : 'white';
    renderBoard();
});

modalResetBtn.addEventListener('click', () => {
    game.reset();
    timers = { w: 600, b: 600 };
    updateClocks();
    if (timerInterval) clearInterval(timerInterval);
    gameStarted = false;
    startBtn.classList.remove('disabled');
    setupArea.style.opacity = '1';
    setupArea.style.pointerEvents = 'all';
    renderBoard();
    socket.emit('reset');
    modal.style.display = 'none';
});

// Initial Render
renderBoard();
