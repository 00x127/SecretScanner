const express = require('express');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);
const path = require('path');

app.use(express.static(path.join(__dirname, 'public')));

let gameState = {
    fen: 'rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1', // Start position
    history: []
};

io.on('connection', (socket) => {
    // Send current state to new player
    socket.emit('init', gameState);

    socket.on('move', (moveData) => {
        // Broadcast move to everyone else
        gameState.fen = moveData.fen;
        socket.broadcast.emit('move', moveData);
    });

    socket.on('reset', () => {
        gameState.fen = 'rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1';
        io.emit('reset');
    });

    socket.on('resign', () => {
        socket.broadcast.emit('resign');
    });

    socket.on('draw_offer', () => {
        socket.broadcast.emit('draw_offer');
    });

    socket.on('draw_accept', () => {
        socket.broadcast.emit('draw_accept');
    });
});

const PORT = process.env.PORT || 3000;
http.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
