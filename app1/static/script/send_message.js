// Function to get a specific cookie by name
function getCookie(name) {
    const value = document.cookie.match('(^|;)\\s*' + name + '\\s*=\\s*([^;]+)');
    return value ? value.pop() : null;
}

// Get the CSRF token from the cookie
function getCSRFToken() {
    return getCookie('csrftoken');
}

// Adding CSRF token to the headers in an Axios request
axios.defaults.headers.common['X-CSRFToken'] = getCSRFToken();

// Now you can make your POST request
document.getElementById('sendMessageForm').addEventListener('submit', function (event) {
    event.preventDefault(); // Prevent form submission

    // Get the receiver and content from the form
    const receiver = document.getElementById('receiver').value.trim();
    const content = document.getElementById('content').value.trim();

    // Validate inputs
    if (!receiver || !content) {
        alert('Please fill in both the receiver and the message content.');
        return;
    }

    // Encrypt the content using AES encryption
    const encryptedContent = CryptoJS.AES.encrypt(content, 'your-secret-key').toString();

    // Retrieve the token from localStorage or cookies
    const tokenFromCookie = getCookie('jwt_token');
    const tokenFromLocalStorage = localStorage.getItem('jwtToken');
    console.log("Token from cookie:", tokenFromCookie);  // Debugging: Log the token from cookie
    console.log("Token from localStorage:", tokenFromLocalStorage);  // Debugging: Log the token from localStorage

    // Use the token from localStorage if available, otherwise from cookies
    const token = tokenFromLocalStorage || tokenFromCookie;
    console.log("Final token to be used:", token);  // Debugging: Log the final token value

    // Check if the token exists before sending the request
    if (!token) {
        alert('No authentication token found. Please log in again.');
        return;
    }

    // Prepare the data to send in the request
    const messageData = {
        receiver: receiver,
        content: encryptedContent,
    };

    // Send the encrypted message to the Django backend
    axios.post('http://127.0.0.1:8000/api/messages/', messageData, {
        headers: {
            'Authorization': `Bearer ${token}`,  // Pass the token as a Bearer token
            'X-CSRFToken': getCSRFToken(),  // Send the CSRF token in the header
            'Content-Type': 'application/json'
        }
    })
    .then(response => {
        if (response.status === 201) {
            console.log('Message sent successfully to App 1:', response.data);
            alert('Message sent successfully to App 1!');
            document.getElementById('sendMessageForm').reset();
        } else {
            throw new Error('Unexpected response status');
        }
    })
    .catch(error => {
        console.error('Error sending message to App 1:', error);
        alert('An error occurred. Please check the console for details.');
    });
});
