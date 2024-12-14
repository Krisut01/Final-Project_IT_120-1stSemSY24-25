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
    // Try localStorage first
    const token = localStorage.getItem('jwtToken');
    if (token) {
        console.log('Token found in localStorage');
        return token;
    }
    
    // Fallback to cookie
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
