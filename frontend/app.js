// INTENTIONALLY VULNERABLE: for SAST/DevSecOps scanner validation only.
const apiKey = 'pk_test_fake_frontend_key'; // fake exposed client secret pattern
const params = new URLSearchParams(window.location.search);
const message = params.get('message') || 'hello';

document.getElementById('output').innerHTML = message; // DOM XSS

function redirect() {
  const next = params.get('next');
  if (next) window.location = next; // open redirect
}

function storeToken(token) {
  localStorage.setItem('jwt', token); // insecure token storage pattern
}

function runExpression() {
  const expr = params.get('expr') || '1+1';
  return eval(expr); // unsafe eval
}

redirect();
storeToken('fake.jwt.token');
console.log('result', runExpression());
