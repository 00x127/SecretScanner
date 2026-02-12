from flask import Flask, request, jsonify, send_from_directory
import subprocess
import os

app = Flask(__name__, static_folder='static', static_url_path='')

# Path to the BetterFish binary
ENGINE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '../BetterFish/target/debug/BetterFish'))

def get_best_move(fen, depth):
    process = subprocess.Popen(
        [ENGINE_PATH],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    commands = f"uci\nisready\nposition fen {fen}\ngo depth {depth}\nquit\n"
    stdout, stderr = process.communicate(input=commands)
    
    for line in stdout.split('\n'):
        if line.startswith('bestmove'):
            return line.split(' ')[1]
    return None

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/move', methods=['POST'])
def move():
    data = request.json
    fen = data.get('fen')
    depth = data.get('depth', 3)
    
    best_move = get_best_move(fen, depth)
    if best_move:
        return jsonify({'best_move': best_move})
    else:
        return jsonify({'error': 'Could not find move'}), 500

if __name__ == '__main__':
    app.run(port=5000, debug=True)

