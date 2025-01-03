from flask import Flask, request, render_template
from waf import wafCheck

app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
    name = request.args.get('name')

    if name :
        if wafCheck(name):
            return "WAF detected a malicious input!"
    
        else:
            message = f"Hello, {name}!"
    
    else:
        message = "Please input your name:"
    
    return render_template('index.html', message=message)

if __name__ == '__main__':
    app.run(debug=True)