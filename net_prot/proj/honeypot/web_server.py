from flask import Flask, Response
import threading
import time

web_server_port = 5000

# Create two Flask web applications
app1 = Flask(__name__)
app2 = Flask(__name__)

@app1.route('/')
def home1():
    def generate():
        for i in range(50):
            yield f"Hello from Interface 1! {i+1}\n"
            time.sleep(1)
    return Response(generate(), mimetype='text/plain')

@app2.route('/')
def home2():
    def generate():
        for i in range(50):
            yield f"Hello from Interface 2! {i+1}\n"
            time.sleep(1)
    return Response(generate(), mimetype='text/plain')

def run_app1():
    app1.run(host='169.254.4.2', port=web_server_port)

def run_app2():
    # app2.run(host='10.133.73.14', port=web_server_port)
    app2.run(host='192.168.1.1', port=web_server_port)
    

if __name__ == "__main__":
    # Run app1 on localhost (169.254.4.2) and port web_server_port
    t1 = threading.Thread(target=run_app1)
    t1.start()

    # Run app2 on the dummy interface (10.133.73.14) and port web_server_port
    t2 = threading.Thread(target=run_app2)
    t2.start()

    t1.join()
    t2.join()