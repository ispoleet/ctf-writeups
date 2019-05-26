function displayMessage(message, peer) {
  var row = document.createElement('p');
  row.className = peer;
  row.textContent = message;
  conversation.appendChild(row);
  if (message == 'Please enter an URL where the administrator can read your report.') {
    window.last_recaptcha_widget = grecaptcha.render(row, {
      sitekey: '6LcpdyEUAAAAANJs8t_yNnYN_N82aP1w7gjoN5k4'
    });
  }
}

csrf_header = new Headers();
csrf_header.append('CSRF-Protection', '1');

function getText(response) {
  return response.text();
}

function sendMessage(msg) {
  var url = '/message?msg=' + encodeURIComponent(msg)
  if (window.last_recaptcha_widget !== undefined) {
    url += '&captcha=' + encodeURIComponent(grecaptcha.getResponse(window.last_recaptcha_widget));
    delete window.last_recaptcha_widget;
  }
  fetch(url, {headers: csrf_header, credentials: 'include'}).then(getText).then(function(res) {
    displayMessage(res, 'joe');
  });
}

window.addEventListener('load', function() {
  messagebox.addEventListener('keydown', function(event) {
    if (event.keyCode == 13 && messagebox.value != '') {
      displayMessage(messagebox.value, 'user');
      sendMessage(messagebox.value);
      messagebox.value = '';
    }
  })
});
