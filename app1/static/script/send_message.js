// Function to get a specific cookie by name
function getCookie(name) {
    const value = document.cookie.match('(^|;)\\s*' + name + '\\s*=\\s*([^;]+)');
    return value ? value.pop() : null;
}

// Get the CSRF token from the cookie
function getCSRFToken() {
    return getCookie('csrftoken');
}

// Function to get the JWT token
function getJWTToken() {
    const token = localStorage.getItem('jwtToken');
    if (token) {
        console.log('Token found in localStorage');
        return token;
    }
    
    const cookieToken = getCookie('jwt_token');
    if (cookieToken) {
        console.log('Token found in cookie');
        return cookieToken;
    }
    
    console.log('No token found');
    return null;
}

// Adding CSRF token to the headers in an Axios request
axios.defaults.headers.common['X-CSRFToken'] = getCSRFToken();

// Now you can make your POST request
document.getElementById('sendMessageForm').addEventListener('submit', function (event) {
    event.preventDefault();

    const receiver = document.getElementById('receiver').value.trim();
    const content = document.getElementById('content').value.trim();

    if (!receiver || !content) {
        alert('Please fill in both the receiver and the message content.');
        return;
    }

    const token = getJWTToken();
    if (!token) {
        alert('No authentication token found. Please log in again.');
        window.location.href = '/login/';
        return;
    }

    const messageData = {
        receiver: receiver,
        content: content
    };

    // Send the message
    axios.post('/api/send-message/', messageData, {
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        }
    })
    .then(response => {
        if (response.status === 201) {
            alert('Message sent successfully!');
            document.getElementById('sendMessageForm').reset();
            loadMessages();  // Refresh messages after sending
        }
    })
    .catch(error => {
        console.error('Error:', error);
        if (error.response && error.response.status === 401) {
            alert('Authentication failed. Please log in again.');
            window.location.href = '/login/';
        } else {
            alert('Failed to send message. Please try again.');
        }
    });
});

function showError(message) {
    const errorDiv = document.getElementById('error-message');
    errorDiv.textContent = message;
    errorDiv.style.display = 'block';
    setTimeout(() => { errorDiv.style.display = 'none'; }, 5000);
}

function showSuccess(message) {
    const successDiv = document.getElementById('success-message');
    successDiv.textContent = message;
    successDiv.style.display = 'block';
    setTimeout(() => { successDiv.style.display = 'none'; }, 5000);
}

async function loadMessages() {
    try {
        const token = getJWTToken();
        if (!token) {
            window.location.href = '/login/';
            return;
        }

        const response = await axios.get('/api/messages/', {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const messagesTable = document.getElementById('messages-table');
        messagesTable.innerHTML = '';  // Clear existing messages

        response.data.forEach(message => {
            const row = document.createElement('tr');
            row.className = 'message-row';
            row.innerHTML = `
                <td>${message.sender}</td>
                <td>${message.receiver}</td>
                <td class="message-content">${message.displayed_content || 'Error: Could not decrypt message'}</td>
                <td class="timestamp">${new Date(message.timestamp).toLocaleString()}</td>
                <td><button onclick="deleteMessage(${message.id})">Delete</button></td>
            `;
            messagesTable.appendChild(row);
        });
    } catch (error) {
        console.error('Error loading messages:', error);
        if (error.response?.status === 401) {
            window.location.href = '/login/';
        } else {
            showError('Error loading messages: ' + (error.response?.data?.error || error.message));
        }
    }
}

async function loadActiveUsers() {
    const token = getJWTToken();
    if (!token) {
        window.location.href = '/login/';
        return;
    }

    const response = await axios.get('/api/messages/', {
        headers: { 'Authorization': `Bearer ${token}` }
    });

    const uniqueUsers = new Set();
    response.data.forEach(message => {
        uniqueUsers.add(message.sender);
        uniqueUsers.add(message.receiver);
    });

    const usersTable = document.getElementById('users-table');
    usersTable.innerHTML = '';  // Clear existing users

    Array.from(uniqueUsers).forEach(username => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${username}</td>
            <td><button onclick="startChat('${username}')">Message</button></td>
        `;
        usersTable.appendChild(row);
    });
}

function startChat(username) {
    document.getElementById('receiver').value = username;
    document.getElementById('content').focus();
}

function deleteMessage(messageId) {
    const token = getJWTToken();
    if (!token) {
        window.location.href = '/login/';
        return;
    }

    axios.delete(`/api/messages/${messageId}/`, {
        headers: { 'Authorization': `Bearer ${token}` }
    })
    .then(response => {
        if (response.status === 204) {  // No Content status
            showSuccess('Message deleted successfully');
            loadMessages();  // Refresh messages
        }
    })
    .catch(error => {
        console.error('Delete message error:', error);
        showError('Failed to delete message: ' + (error.response?.data?.error || error.message));
    });
}

document.addEventListener('DOMContentLoaded', async function() {
    const token = getJWTToken();
    if (!token) {
        window.location.href = '/login/';
        return;
    }

    document.getElementById('sendMessageForm').addEventListener('submit', sendMessage);
    
    await loadMessages();
    await loadActiveUsers();
    
    // Auto refresh
    setInterval(async () => {
        await loadMessages();
        await loadActiveUsers();
    }, 10000);
});