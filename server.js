var fs = require('fs'),
    http = require('http'),
    sio = require('socket.io'),
    express=require('express'),
    app = express(),
    cookie = require('cookie'),
    util = require("util");
var helpers = require('./helpers');

var SECRET_KEY = 'YOUR_LARAVEL_SECRET_KEY_HERE';

app.configure(function () {
    app.use(express.cookieParser());
});

server = http.createServer(app)
server.listen(8000, function() {
  console.log('Server listening at http://localhost:8000/');
});

io = sio.listen(server);
io.set('authorization', function (handshakeData, accept) {
  if (handshakeData.headers.cookie) {
    handshakeData.cookie = cookie.parse(handshakeData.headers.cookie);
    var laravelSession = JSON.parse(new Buffer(decodeURI(handshakeData.cookie['laravel_session']), 'base64').toString());

    var laravelSessionIv = new Buffer(laravelSession.iv, 'base64');
    var laravelSessionValue = new Buffer(laravelSession.value, 'base64');
    var laravelSessionMac = new Buffer(laravelSession.mac, 'base64');

    if(!helpers.validMac(SECRET_KEY, laravelSession.mac, laravelSession.iv, laravelSession.value)) {
      return accept('Cookie is invalid.', false)
    }

    var sessionId = helpers.decryptSession(SECRET_KEY, laravelSessionIv, laravelSessionValue);

    if (sessionId == null) {
      return accept('Cookie is invalid.', false);
    }

    helpers.getUserIdFromSessionId(sessionId, function(_id) {
      accept(null, true);
    });

  } else {
    return accept('No cookie transmitted.', false);
  }
});

var messages = [];
io.sockets.on('connection', function (socket) {
  console.log('New connection!');
  socket.on('message', function (msg) {
    console.log('Received: ', msg);
    messages.push(msg);
    socket.broadcast.emit('message', msg);
  });
  messages.forEach(function(msg) {
    socket.send(msg);
  });
});
