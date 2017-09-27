from flask import Flask
app=Flask(__name__)

#默认的主页
@app.route('/')
def index():
	return '<h1>Hello World</h1>'

#根据地址栏http://127.0.0.1:5000/user/dave 页面名字根据地址栏名字显示，
@app.route('/user/<name>')
def user(name):
	return '<h1>Hello,%s!</h1>' %name


if __name__=='__main__':
	app.run(debug=True)