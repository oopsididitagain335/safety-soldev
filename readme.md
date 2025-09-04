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
