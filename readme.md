# Anti-DDoS CAPTCHA API

A Flask-based service providing an API for anti-DDoS protection using proof-of-work CAPTCHA, rate-limiting, IP blacklisting, and traffic redirection. Automatically adds a footer to client sites: "Protected And Supported By SolDev Security".

## Deployment on Render

1. Create a new Web Service on Render.
2. Connect your GitHub repo.
3. Set build command: `pip install -r requirements.txt`
4. Set start command: `python app.py`
5. Add environment variable: `SECRET_KEY` (generate a secure key).

## Integration

1. Generate an API key from `/dashboard`.
2. Add `<script src="https://yourdomain.com/api/client_script/YOUR_API_KEY"></script>` to your site.
3. The script handles DDoS protection and adds the SolDev Security footer.

The system redirects malicious traffic to an invalid domain, blacklists IPs, and uses threading and queuing to handle heavy loads in worst-case scenarios.

SolDev Security Anti-DDoS API Instructions
The SolDev Security Anti-DDoS API provides Cloudflare-level protection for your website by using a proof-of-work CAPTCHA, rate-limiting, IP blacklisting, and traffic redirection. It automatically adds a footer to your site: "Protected And Supported By SolDev Security". Follow these steps to integrate and use the API effectively.
Prerequisites

A website where you can add a <script> tag in the HTML.
Access to the SolDev Security API at https://safety-soldev.onrender.com.
Basic knowledge of HTTP requests and JavaScript.

Step-by-Step Integration
1. Generate an API Key

Visit the SolDev Security dashboard at https://safety-soldev.onrender.com/dashboard.
Click the "Generate API Key" button.
Copy the generated API key (e.g., fWjnB9TqXKV29bUQ3TtGGi3pcVZsqNYS).
Store the API key securely, as it will be used in all API requests.

2. Add the Client Script to Your Website

Add the following <script> tag to the <head> or <body> of your website’s HTML:
<script src="https://safety-soldev.onrender.com/api/client_script/YOUR_API_KEY"></script>

Replace YOUR_API_KEY with your generated API key.

The script will:

Initiate DDoS protection by requesting a challenge from the API.
Automatically append a footer to your site: "Protected And Supported By SolDev Security".
Handle the proof-of-work CAPTCHA challenge in the background when rate limits are exceeded.
Store a JWT token in localStorage (key: ddos_token) upon successful CAPTCHA verification.



3. Understanding API Functionality
The API protects your site by:

Rate-Limiting: Limits requests to 20 per minute per IP. Exceeding this triggers a CAPTCHA challenge.
CAPTCHA Challenge: Requires clients to solve a proof-of-work task (MD5 hash with 4 leading zeros).
IP Blacklisting: Blocks IPs for 30 minutes if they fail the CAPTCHA or exceed rate limits.
Traffic Redirection: Redirects malicious traffic to an invalid domain (127.0.0.1:9999).
JWT Authentication: Issues a token valid for 1 hour, tied to the client’s IP, for accessing protected content.

4. Accessing Protected Content
To access protected content on your site, use the JWT token stored by the client script:

Make a request to your protected endpoint, including the token in the Authorization header.

Example using JavaScript:
const token = localStorage.getItem('ddos_token');
fetch('/protected', {
    headers: {
        'Authorization': `Bearer ${token}`
    }
})
.then(res => res.json())
.then(data => console.log(data))
.catch(err => console.error('Error:', err));


To verify the token with the SolDev API, make a request to:
GET https://safety-soldev.onrender.com/api/protected
Headers:
    X-API-KEY: YOUR_API_KEY
    Authorization: Bearer YOUR_JWT_TOKEN
    Content-Type: application/json


Success Response (200):{"message": "Access granted - Protected content"}


Error Responses:
401: {"error": "Invalid API Key"} or {"error": "Unauthorized"}
403: {"error": "Invalid solution"} (failed CAPTCHA)





5. Testing the API
To test the API integration:

Deploy a test site (e.g., using the provided test site code) or add the script to an existing site.
Load the site and verify the footer appears: "Protected And Supported By SolDev Security".
Simulate rapid requests (e.g., using curl or ab) to trigger rate-limiting:for i in {1..30}; do curl https://your-test-site.com; done


Expect a redirect to http://127.0.0.1:9999 for excessive requests.


Check the browser’s localStorage for the ddos_token after the CAPTCHA is solved.
Make a request to the /protected endpoint with the token to confirm access.

6. API Endpoints

Generate Challenge:
GET https://safety-soldev.onrender.com/api/challenge
Headers:
    X-API-KEY: YOUR_API_KEY

Returns an HTML page with a JavaScript-based CAPTCHA challenge.

Verify Solution:
POST https://safety-soldev.onrender.com/api/verify
Headers:
    X-API-KEY: YOUR_API_KEY
    Content-Type: application/json
Body:
    {
        "challenge": "CHALLENGE_STRING",
        "nonce": NONCE_VALUE
    }

Returns a JWT token on success.

Access Protected Content:
GET https://safety-soldev.onrender.com/api/protected
Headers:
    X-API-KEY: YOUR_API_KEY
    Authorization: Bearer YOUR_JWT_TOKEN

Returns protected content or an error.

Client Script:
GET https://safety-soldev.onrender.com/api/client_script/YOUR_API_KEY

Returns the JavaScript for DDoS protection and footer insertion.


7. Handling DDoS Protection

Normal Traffic: Users access your site without interruption, and the footer is added.
Suspicious Traffic: If an IP exceeds 20 requests per minute, the API serves a CAPTCHA challenge.
Malicious Traffic: Failed CAPTCHAs or continued abuse result in IP blacklisting and redirection to an invalid domain.
Resilience: The API uses threading and queuing to handle heavy loads, ensuring stability even under worst-case DDoS attacks.

8. Troubleshooting

No Footer: Ensure the <script> tag is correctly added and the API key is valid.
No Token in localStorage: Check if the CAPTCHA challenge loaded (view browser console for errors).
401/403 Errors: Verify the API key and token are correctly included in requests. Ensure the IP matches the token’s IP.
Redirect to Invalid Domain: Indicates rate-limiting or blacklisting; wait 30 minutes or solve the CAPTCHA correctly.
API Unreachable: Confirm the API URL (https://safety-soldev.onrender.com) is correct and the service is running.

9. Security Notes

Keep your API key confidential.
Use HTTPS for all requests to prevent token interception.
Monitor your site’s traffic to adjust rate-limiting thresholds if needed (contact SolDev support for customization).
The API’s proof-of-work difficulty (4 leading zeros) ensures computational cost for attackers, deterring bots.

For further assistance, visit https://safety-soldev.onrender.com/docs or contact SolDev Security support.
