var socket = io();
var userId = "{{ user_id }}"; // Current user ID

document.getElementById('sendButton').onclick = function() {
    var messageInput = document.getElementById('messageInput');
    var message = messageInput.value;
    if (message) {
        // Emit the message with sender and receiver info
        socket.emit('send_message', { receiver_id: userId, message: message });
        messageInput.value = '';
    }
};

socket.on('receive_message', function(data) {
    var messagesList = document.getElementById('messages');
    var item = document.createElement('li');
    item.textContent = data.sender_id + ': ' + data.message;
    messagesList.appendChild(item);
});

// Join the chat room
socket.emit('join', { user_id: userId });