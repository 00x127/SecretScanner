var board = null
var game = new Chess()
var $status = $('#status')
var playerColor = 'white'

function onDragStart (source, piece, position, orientation) {
  // do not pick up pieces if the game is over
  if (game.game_over()) return false

  // only pick up pieces for the player color
  if ((playerColor === 'white' && piece.search(/^b/) !== -1) ||
      (playerColor === 'black' && piece.search(/^w/) !== -1)) {
    return false
  }

  // only pick up pieces for the side to move
  if ((game.turn() === 'w' && piece.search(/^b/) !== -1) ||
      (game.turn() === 'b' && piece.search(/^w/) !== -1)) {
    return false
  }
}

function makeEngineMove () {
  var fen = game.fen()
  var depth = $('#depth').val()

  $status.html('Engine is thinking...')

  $.ajax({
    url: '/move',
    type: 'POST',
    contentType: 'application/json',
    data: JSON.stringify({ fen: fen, depth: parseInt(depth) }),
    success: function (data) {
      if (data.best_move) {
        // Handle UCI moves like 'e2e4' or 'e7e8q'
        var move = {
          from: data.best_move.substring(0, 2),
          to: data.best_move.substring(2, 4),
          promotion: data.best_move.length > 4 ? data.best_move.substring(4, 5) : 'q'
        }
        
        game.move(move)
        board.position(game.fen())
        updateStatus()
      }
    },
    error: function() {
      $status.html('Error communicating with engine.')
    }
  })
}

function onDrop (source, target) {
  // see if the move is legal
  var move = game.move({
    from: source,
    to: target,
    promotion: 'q' // NOTE: always promote to a queen for example simplicity
  })

  // illegal move
  if (move === null) return 'snapback'

  updateStatus()

  // make engine move after a short delay
  window.setTimeout(makeEngineMove, 250)
}

// update the board position after the piece snap
// for castling, en passant, pawn promotion
function onSnapEnd () {
  board.position(game.fen())
}

function updateStatus () {
  var status = ''

  var moveColor = 'White'
  if (game.turn() === 'b') {
    moveColor = 'Black'
  }

  // checkmate?
  if (game.in_checkmate()) {
    status = 'Game over, ' + moveColor + ' is in checkmate.'
  }
  // draw?
  else if (game.in_draw()) {
    status = 'Game over, drawn position'
  }
  // game still on
  else {
    status = moveColor + ' to move'
    // check?
    if (game.in_check()) {
      status += ', ' + moveColor + ' is in check'
    }
  }

  $status.html(status)
}

var config = {
  draggable: true,
  position: 'start',
  onDragStart: onDragStart,
  onDrop: onDrop,
  onSnapEnd: onSnapEnd,
  pieceTheme: 'https://chessboardjs.com/img/chesspieces/wikipedia/{piece}.png'
}
board = Chessboard('board', config)

updateStatus()

$('#reset').on('click', function() {
    game.reset()
    board.start()
    playerColor = $('#color').val()
    board.orientation(playerColor)
    updateStatus()
    if (playerColor === 'black') {
        window.setTimeout(makeEngineMove, 250)
    }
})

$('#undo').on('click', function() {
    game.undo()
    game.undo()
    board.position(game.fen())
    updateStatus()
    
    // If it's now the engine's turn (e.g. playing as black and undid back to start), trigger engine
    if ((playerColor === 'black' && game.turn() === 'w') ||
        (playerColor === 'white' && game.turn() === 'b')) {
        window.setTimeout(makeEngineMove, 250)
    }
})

$('#color').on('change', function() {
    playerColor = $(this).val()
    board.orientation(playerColor)
    game.reset()
    board.start()
    updateStatus()
    if (playerColor === 'black') {
        window.setTimeout(makeEngineMove, 250)
    }
})
