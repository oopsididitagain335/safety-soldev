function initDDoSProtection(apiKey) {
  var xhr = new XMLHttpRequest();
  xhr.open('GET', '/api/challenge', true);
  xhr.setRequestHeader('X-API-KEY', apiKey);
  xhr.onreadystatechange = function() {
    if (xhr.readyState === 4 && xhr.status === 200) {
      var parser = new DOMParser();
      var doc = parser.parseFromString(xhr.responseText, 'text/html');
      var script = doc.querySelector('script:not([src])').innerText;
      eval(script);
    }
  };
  xhr.send();
  var footer = document.createElement('footer');
  footer.style = 'text-align: center; padding: 10px; background: #f8f8f8;';
  footer.innerHTML = 'Protected And Supported By <a href="https://yourdomain.com">SolDev Security</a>';
  document.body.appendChild(footer);
}
